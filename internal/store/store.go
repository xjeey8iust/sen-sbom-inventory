// Package store owns the SQLite file and every write the service performs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// ErrConflict reports that an SBOM with the same artifact and version already
// exists and its content differs from the submitted one.
var ErrConflict = errors.New("sbom conflict")

// Component is one normalized component row belonging to an SBOM.
type Component struct {
	Coordinate   string
	License      string
	Dependencies []string
}

// SBOM is one complete manifest: header plus every component it contains.
type SBOM struct {
	ID         int64
	Artifact   string
	Version    string
	Components []Component
}

// RegisterOutcome reports what RegisterSBOM did with a submission.
type RegisterOutcome struct {
	SBOM    *SBOM
	Created bool
}

// RegisterSBOM inserts a manifest together with all of its components and
// dependencies in a single transaction. If the same artifact and version is
// already registered, the stored manifest is compared against the submission
// independently of row order: equal content returns the existing record with
// Created set to false, different content returns ErrConflict and leaves the
// stored record untouched.
func (s *Store) RegisterSBOM(ctx context.Context, artifact, version string, components []Component) (*RegisterOutcome, error) {
	// Normalize order at the persistence boundary so equality never depends on
	// how the caller ordered the arrays; stored rows are sorted the same way.
	components = append([]Component(nil), components...)
	for i := range components {
		components[i].Dependencies = append([]string(nil), components[i].Dependencies...)
		sort.Strings(components[i].Dependencies)
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Coordinate < components[j].Coordinate
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin register tx: %w", err)
	}
	defer tx.Rollback()

	var existingID int64
	switch err := tx.QueryRowContext(ctx,
		`SELECT id FROM sboms WHERE artifact = ? AND version = ?`,
		artifact, version,
	).Scan(&existingID); {
	case errors.Is(err, sql.ErrNoRows):
		// New manifest; fall through to the insert path.
	case err != nil:
		return nil, fmt.Errorf("lookup existing sbom: %w", err)
	default:
		existing, err := loadSBOM(ctx, tx, existingID)
		if err != nil {
			return nil, err
		}
		if manifestsEqual(existing, components) {
			return &RegisterOutcome{SBOM: existing, Created: false}, nil
		}
		return nil, ErrConflict
	}

	result, err := tx.ExecContext(ctx,
		`INSERT INTO sboms (artifact, version) VALUES (?, ?)`,
		artifact, version)
	if err != nil {
		return nil, fmt.Errorf("insert sbom: %w", err)
	}
	sbomID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read sbom id: %w", err)
	}

	for _, comp := range components {
		compResult, err := tx.ExecContext(ctx,
			`INSERT INTO components (sbom_id, coordinate, license) VALUES (?, ?, ?)`,
			sbomID, comp.Coordinate, comp.License)
		if err != nil {
			return nil, fmt.Errorf("insert component: %w", err)
		}
		compID, err := compResult.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("read component id: %w", err)
		}
		for _, dep := range comp.Dependencies {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO dependencies (component_id, dependency_coordinate) VALUES (?, ?)`,
				compID, dep); err != nil {
				return nil, fmt.Errorf("insert dependency: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit register tx: %w", err)
	}

	created := &SBOM{ID: sbomID, Artifact: artifact, Version: version, Components: components}
	return &RegisterOutcome{SBOM: created, Created: true}, nil
}

// ListSBOMs returns a page of complete manifests for one artifact ordered by
// manifest id, together with the total number of matching manifests.
func (s *Store) ListSBOMs(ctx context.Context, artifact string, page, pageSize int) (items []*SBOM, total int, err error) {
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sboms WHERE artifact = ?`, artifact,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sboms: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, artifact, version FROM sboms
		 WHERE artifact = ?
		 ORDER BY id ASC
		 LIMIT ? OFFSET ?`,
		artifact, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("query sbom page: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var sbom SBOM
		if err := rows.Scan(&sbom.ID, &sbom.Artifact, &sbom.Version); err != nil {
			return nil, 0, fmt.Errorf("scan sbom: %w", err)
		}
		ids = append(ids, sbom.ID)
		items = append(items, &sbom)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate sbom page: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("close sbom page: %w", err)
	}

	for i, id := range ids {
		loaded, err := loadSBOM(ctx, s.db, id)
		if err != nil {
			return nil, 0, err
		}
		items[i].Components = loaded.Components
	}
	return items, total, nil
}

// sbomQuerier is satisfied by both *sql.DB and *sql.Tx.
type sbomQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// loadSBOM reads one manifest and all of its detail rows through q.
func loadSBOM(ctx context.Context, q sbomQuerier, id int64) (*SBOM, error) {
	sbom := &SBOM{ID: id}
	if err := q.QueryRowContext(ctx,
		`SELECT artifact, version FROM sboms WHERE id = ?`, id,
	).Scan(&sbom.Artifact, &sbom.Version); err != nil {
		return nil, fmt.Errorf("load sbom %d: %w", id, err)
	}

	rows, err := q.QueryContext(ctx,
		`SELECT id, coordinate, license FROM components
		 WHERE sbom_id = ?
		 ORDER BY coordinate ASC`, id)
	if err != nil {
		return nil, fmt.Errorf("load components for sbom %d: %w", id, err)
	}
	defer rows.Close()

	type pendingComponent struct {
		comp *Component
		id   int64
	}
	var pending []pendingComponent
	var compIDs []int64
	for rows.Next() {
		var pc pendingComponent
		pc.comp = &Component{Dependencies: []string{}}
		if err := rows.Scan(&pc.id, &pc.comp.Coordinate, &pc.comp.License); err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		pending = append(pending, pc)
		compIDs = append(compIDs, pc.id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate components: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close components: %w", err)
	}

	depsByComponent := make(map[int64][]string, len(compIDs))
	if len(compIDs) > 0 {
		depRows, err := q.QueryContext(ctx,
			`SELECT component_id, dependency_coordinate FROM dependencies
			 WHERE component_id IN (`+placeholders(len(compIDs))+`)
			 ORDER BY component_id ASC, dependency_coordinate ASC`,
			int64SliceToAny(compIDs)...)
		if err != nil {
			return nil, fmt.Errorf("load dependencies for sbom %d: %w", id, err)
		}
		defer depRows.Close()
		for depRows.Next() {
			var componentID int64
			var coordinate string
			if err := depRows.Scan(&componentID, &coordinate); err != nil {
				return nil, fmt.Errorf("scan dependency: %w", err)
			}
			depsByComponent[componentID] = append(depsByComponent[componentID], coordinate)
		}
		if err := depRows.Err(); err != nil {
			return nil, fmt.Errorf("iterate dependencies: %w", err)
		}
		if err := depRows.Close(); err != nil {
			return nil, fmt.Errorf("close dependencies: %w", err)
		}
	}

	sbom.Components = make([]Component, 0, len(pending))
	for _, pc := range pending {
		if deps, ok := depsByComponent[pc.id]; ok {
			pc.comp.Dependencies = deps
		}
		sbom.Components = append(sbom.Components, *pc.comp)
	}
	return sbom, nil
}

// manifestsEqual compares two manifests independently of component order.
// Both inputs use the API's normalized representation: components and their
// dependency lists are coordinate-sorted with distinct entries.
func manifestsEqual(a *SBOM, components []Component) bool {
	if len(a.Components) != len(components) {
		return false
	}
	for i := range a.Components {
		left, right := a.Components[i], components[i]
		if left.Coordinate != right.Coordinate || left.License != right.License ||
			len(left.Dependencies) != len(right.Dependencies) {
			return false
		}
		for j := range left.Dependencies {
			if left.Dependencies[j] != right.Dependencies[j] {
				return false
			}
		}
	}
	return true
}

// placeholders returns "?,?,..." with n question marks.
func placeholders(n int) string {
	return strings.Repeat("?,", n-1) + "?"
}

func int64SliceToAny(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sboms (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	artifact TEXT NOT NULL,
	version  TEXT NOT NULL,
	UNIQUE (artifact, version)
);

CREATE TABLE IF NOT EXISTS components (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	sbom_id    INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
	coordinate TEXT NOT NULL,
	license    TEXT NOT NULL,
	UNIQUE (sbom_id, coordinate)
);

CREATE TABLE IF NOT EXISTS dependencies (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	component_id          INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
	dependency_coordinate TEXT NOT NULL,
	UNIQUE (component_id, dependency_coordinate)
);
`
