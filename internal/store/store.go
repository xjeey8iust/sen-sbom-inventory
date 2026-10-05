// Package store owns the SQLite file and every write the service performs.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	dsn := path
	if strings.Contains(dsn, "?") {
		dsn += "&"
	} else {
		dsn += "?"
	}
	// foreign_keys must be enabled per connection; busy_timeout lets a
	// concurrent writer wait for an open write transaction instead of
	// failing immediately with SQLITE_BUSY.
	dsn += "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
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

// queryer is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Register persists a normalized SBOM in a single write transaction. When the
// same artifact and version already hold an identical manifest, the existing
// record (with its original ID) is returned and created is false. Different
// content leaves the existing record untouched and returns model.ErrConflict.
func (s *Store) Register(ctx context.Context, in *model.SBOM) (sbom *model.SBOM, created bool, err error) {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, unavailable(err)
	}
	defer c.Close()

	// BEGIN IMMEDIATE takes the writer lock up front, so two concurrent
	// registrations for the same artifact/version serialize and the loser
	// re-reads the winner's committed row instead of hitting the unique
	// constraint.
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, false, unavailable(err)
	}
	committed := false
	defer func() {
		if !committed {
			// Best-effort cleanup; the original error is what callers need.
			_, _ = c.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var existingID int64
	switch err := c.QueryRowContext(ctx,
		"SELECT id FROM sboms WHERE artifact = ? AND version = ?",
		in.Artifact, in.Version,
	).Scan(&existingID); {
	case err == nil:
		existing, err := loadSBOM(ctx, c, existingID)
		if err != nil {
			return nil, false, err
		}
		if !equalContent(existing, in) {
			return nil, false, model.ErrConflict
		}
		return existing, false, nil
	case errors.Is(err, sql.ErrNoRows):
		// Continue and insert.
	default:
		return nil, false, unavailable(err)
	}

	res, err := c.ExecContext(ctx,
		"INSERT INTO sboms (artifact, version) VALUES (?, ?)",
		in.Artifact, in.Version)
	if err != nil {
		return nil, false, unavailable(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, false, unavailable(err)
	}

	componentID := make(map[string]int64, len(in.Components))
	insertComponent, err := c.PrepareContext(ctx,
		"INSERT INTO components (sbom_id, coordinate, license) VALUES (?, ?, ?)")
	if err != nil {
		return nil, false, unavailable(err)
	}
	defer insertComponent.Close()
	for i := range in.Components {
		comp := &in.Components[i]
		res, err := insertComponent.ExecContext(ctx, id, comp.Coordinate, comp.License)
		if err != nil {
			return nil, false, unavailable(err)
		}
		compID, err := res.LastInsertId()
		if err != nil {
			return nil, false, unavailable(err)
		}
		componentID[comp.Coordinate] = compID
	}

	if depCount := countDependencies(in); depCount > 0 {
		insertDep, err := c.PrepareContext(ctx,
			"INSERT INTO dependencies (component_id, target_id) VALUES (?, ?)")
		if err != nil {
			return nil, false, unavailable(err)
		}
		defer insertDep.Close()
		for i := range in.Components {
			comp := &in.Components[i]
			for _, dep := range comp.Dependencies {
				if _, err := insertDep.ExecContext(ctx, componentID[comp.Coordinate], componentID[dep]); err != nil {
					return nil, false, unavailable(err)
				}
			}
		}
	}

	if _, err := c.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, false, unavailable(err)
	}
	committed = true

	out := *in
	out.ID = id
	return &out, true, nil
}

// List returns one page of complete SBOMs for an artifact ordered by ID, plus
// the total number of matching manifests. Both reads run in one transaction so
// the count and the page share the same snapshot.
func (s *Store) List(ctx context.Context, artifact string, page, pageSize int) (items []*model.SBOM, total int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, unavailable(err)
	}
	defer tx.Rollback()

	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sboms WHERE artifact = ?", artifact,
	).Scan(&total); err != nil {
		return nil, 0, unavailable(err)
	}

	rows, err := tx.QueryContext(ctx,
		"SELECT id FROM sboms WHERE artifact = ? ORDER BY id ASC LIMIT ? OFFSET ?",
		artifact, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, unavailable(err)
	}
	defer rows.Close()

	items = []*model.SBOM{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, 0, unavailable(err)
		}
		sbom, err := loadSBOM(ctx, tx, id)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, sbom)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, unavailable(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, unavailable(err)
	}
	return items, total, nil
}

// loadSBOM reconstructs a full manifest with components ordered by coordinate
// and each component's dependencies ordered by the target coordinate.
func loadSBOM(ctx context.Context, q queryer, id int64) (*model.SBOM, error) {
	sbom := &model.SBOM{ID: id, Components: []model.Component{}}
	if err := q.QueryRowContext(ctx,
		"SELECT artifact, version FROM sboms WHERE id = ?", id,
	).Scan(&sbom.Artifact, &sbom.Version); err != nil {
		return nil, unavailable(err)
	}

	componentRows, err := q.QueryContext(ctx,
		"SELECT coordinate, license FROM components WHERE sbom_id = ? ORDER BY coordinate ASC", id)
	if err != nil {
		return nil, unavailable(err)
	}
	defer componentRows.Close()

	indexByCoordinate := make(map[string]int)
	for componentRows.Next() {
		var comp model.Component
		comp.Dependencies = []string{}
		if err := componentRows.Scan(&comp.Coordinate, &comp.License); err != nil {
			return nil, unavailable(err)
		}
		indexByCoordinate[comp.Coordinate] = len(sbom.Components)
		sbom.Components = append(sbom.Components, comp)
	}
	if err := componentRows.Err(); err != nil {
		return nil, unavailable(err)
	}

	depRows, err := q.QueryContext(ctx, `
SELECT sc.coordinate, tc.coordinate
FROM dependencies d
JOIN components sc ON sc.id = d.component_id
JOIN components tc ON tc.id = d.target_id
WHERE sc.sbom_id = ?
ORDER BY sc.coordinate ASC, tc.coordinate ASC`, id)
	if err != nil {
		return nil, unavailable(err)
	}
	defer depRows.Close()

	for depRows.Next() {
		var from, to string
		if err := depRows.Scan(&from, &to); err != nil {
			return nil, unavailable(err)
		}
		comp := &sbom.Components[indexByCoordinate[from]]
		comp.Dependencies = append(comp.Dependencies, to)
	}
	if err := depRows.Err(); err != nil {
		return nil, unavailable(err)
	}
	return sbom, nil
}

// equalContent compares normalized manifests (sorted components and
// dependencies); artifact and version already matched in SQL.
func equalContent(a, b *model.SBOM) bool {
	if len(a.Components) != len(b.Components) {
		return false
	}
	for i := range a.Components {
		x, y := &a.Components[i], &b.Components[i]
		if x.Coordinate != y.Coordinate || x.License != y.License {
			return false
		}
		if len(x.Dependencies) != len(y.Dependencies) {
			return false
		}
		for j := range x.Dependencies {
			if x.Dependencies[j] != y.Dependencies[j] {
				return false
			}
		}
	}
	return true
}

func countDependencies(in *model.SBOM) int {
	n := 0
	for i := range in.Components {
		n += len(in.Components[i].Dependencies)
	}
	return n
}

func unavailable(err error) error {
	if errors.Is(err, model.ErrStorageUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %v", model.ErrStorageUnavailable, err)
}

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sboms (
    id       INTEGER PRIMARY KEY,
    artifact TEXT NOT NULL,
    version  TEXT NOT NULL,
    UNIQUE (artifact, version)
);
CREATE TABLE IF NOT EXISTS components (
    id         INTEGER PRIMARY KEY,
    sbom_id    INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    coordinate TEXT NOT NULL,
    license    TEXT NOT NULL,
    UNIQUE (sbom_id, coordinate)
);
CREATE TABLE IF NOT EXISTS dependencies (
    id           INTEGER PRIMARY KEY,
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    target_id    INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    UNIQUE (component_id, target_id)
);
CREATE INDEX IF NOT EXISTS idx_sboms_artifact ON sboms(artifact);
`
