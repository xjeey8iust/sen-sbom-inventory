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
	return open(path, "sqlite")
}

// open is Open with an injectable driver name, which lets the package tests
// register a driver wrapper around the real SQLite driver.
func open(path, driverName string) (*Store, error) {
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

	db, err := sql.Open(driverName, dsn)
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

// Transaction open modes used by the store entry points.
const (
	// beginImmediate takes the writer lock up front, so two concurrent
	// registrations for the same artifact/version serialize and the loser
	// re-reads the winner's committed row instead of hitting the unique
	// constraint.
	beginImmediate = "BEGIN IMMEDIATE"
	// beginDeferred opens a read transaction that pins one snapshot for every
	// SELECT of the transaction.
	beginDeferred = "BEGIN"
)

// withTx is the single transaction lifecycle rule of the store, shared by
// Register and List. It checks out a dedicated connection, opens the
// transaction with the given begin statement, runs fn, and commits when fn
// succeeds. Every exit path — normal return or early exit on any failure —
// finishes the transaction and returns the connection to the pool:
//
//   - connection acquisition, BEGIN and COMMIT failures are reported as
//     model.ErrStorageUnavailable;
//   - fn's own errors (business errors like model.ErrConflict, or storage
//     errors fn already wrapped) propagate to the caller unchanged;
//   - any exit before COMMIT runs a best-effort ROLLBACK, so a failed write
//     never leaves partial records behind; a rollback failure is swallowed
//     and never replaces the business or storage error that caused it.
func (s *Store) withTx(ctx context.Context, begin string, fn func(c *sql.Conn) error) error {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return unavailable(err)
	}
	defer c.Close()

	if _, err := c.ExecContext(ctx, begin); err != nil {
		return unavailable(err)
	}
	committed := false
	defer func() {
		if !committed {
			// Best-effort cleanup; the original error is what callers need.
			_, _ = c.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if err := fn(c); err != nil {
		return err
	}
	if _, err := c.ExecContext(ctx, "COMMIT"); err != nil {
		return unavailable(err)
	}
	committed = true
	return nil
}

// Register persists a normalized SBOM in a single write transaction. When the
// same artifact and version already hold an identical manifest, the existing
// record (with its original ID) is returned and created is false. Different
// content leaves the existing record untouched and returns model.ErrConflict.
func (s *Store) Register(ctx context.Context, in *model.SBOM) (sbom *model.SBOM, created bool, err error) {
	err = s.withTx(ctx, beginImmediate, func(c *sql.Conn) error {
		var existingID int64
		switch err := c.QueryRowContext(ctx,
			"SELECT id FROM sboms WHERE artifact = ? AND version = ?",
			in.Artifact, in.Version,
		).Scan(&existingID); {
		case err == nil:
			existing, err := loadSBOM(ctx, c, existingID)
			if err != nil {
				return err
			}
			if !equalContent(existing, in) {
				return model.ErrConflict
			}
			sbom, created = existing, false
			return nil
		case errors.Is(err, sql.ErrNoRows):
			// Continue and insert.
		default:
			return unavailable(err)
		}

		res, err := c.ExecContext(ctx,
			"INSERT INTO sboms (artifact, version) VALUES (?, ?)",
			in.Artifact, in.Version)
		if err != nil {
			return unavailable(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return unavailable(err)
		}

		componentID := make(map[string]int64, len(in.Components))
		insertComponent, err := c.PrepareContext(ctx,
			"INSERT INTO components (sbom_id, coordinate, license) VALUES (?, ?, ?)")
		if err != nil {
			return unavailable(err)
		}
		defer insertComponent.Close()
		for i := range in.Components {
			comp := &in.Components[i]
			res, err := insertComponent.ExecContext(ctx, id, comp.Coordinate, comp.License)
			if err != nil {
				return unavailable(err)
			}
			compID, err := res.LastInsertId()
			if err != nil {
				return unavailable(err)
			}
			componentID[comp.Coordinate] = compID
		}

		if depCount := countDependencies(in); depCount > 0 {
			insertDep, err := c.PrepareContext(ctx,
				"INSERT INTO dependencies (component_id, target_id) VALUES (?, ?)")
			if err != nil {
				return unavailable(err)
			}
			defer insertDep.Close()
			for i := range in.Components {
				comp := &in.Components[i]
				for _, dep := range comp.Dependencies {
					if _, err := insertDep.ExecContext(ctx, componentID[comp.Coordinate], componentID[dep]); err != nil {
						return unavailable(err)
					}
				}
			}
		}

		out := *in
		out.ID = id
		sbom, created = &out, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return sbom, created, nil
}

// List returns one page of complete SBOMs for an artifact ordered by ID, plus
// the total number of matching manifests. The count, the page manifests and
// the components/dependencies of that page are each read in one batched query
// (four SELECTs at most, regardless of page size) inside one transaction, so
// the total and the details share one committed snapshot and detail rows are
// never fetched for other pages or other artifacts. The detail reads go
// through the same loadComponentsInto/loadDependenciesInto loaders that
// Register's idempotency check uses, keeping one reconstruction rule.
func (s *Store) List(ctx context.Context, artifact string, page, pageSize int) (items []*model.SBOM, total int, err error) {
	err = s.withTx(ctx, beginDeferred, func(c *sql.Conn) error {
		if err := c.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sboms WHERE artifact = ?", artifact,
		).Scan(&total); err != nil {
			return unavailable(err)
		}

		rows, err := c.QueryContext(ctx,
			"SELECT id, artifact, version FROM sboms WHERE artifact = ? ORDER BY id ASC LIMIT ? OFFSET ?",
			artifact, pageSize, (page-1)*pageSize)
		if err != nil {
			return unavailable(err)
		}
		defer rows.Close()

		items = []*model.SBOM{}
		ids := make([]int64, 0, pageSize)
		indexByID := make(map[int64]int, pageSize)
		for rows.Next() {
			sbom := &model.SBOM{Components: []model.Component{}}
			if err := rows.Scan(&sbom.ID, &sbom.Artifact, &sbom.Version); err != nil {
				return unavailable(err)
			}
			ids = append(ids, sbom.ID)
			indexByID[sbom.ID] = len(items)
			items = append(items, sbom)
		}
		if err := rows.Err(); err != nil {
			return unavailable(err)
		}

		// Empty page (unknown artifact or a page past the last one): the count
		// was already read, and the two detail queries must not run with an
		// empty IN list. Total is still returned to the caller.
		if len(ids) == 0 {
			return nil
		}

		if err := loadComponentsInto(ctx, c, items, ids, indexByID); err != nil {
			return err
		}
		if err := loadDependenciesInto(ctx, c, items, ids, indexByID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// loadComponentsInto reads every component of the given manifests in one
// query and attaches the ordered components to their manifests. It is the
// single component reconstruction rule of the service: List calls it for the
// current page, and Register's idempotency/conflict check calls it (through
// loadSBOM) for the one stored manifest, so both read paths rebuild
// components exactly the same way.
func loadComponentsInto(ctx context.Context, q queryer, items []*model.SBOM, ids []int64, indexByID map[int64]int) error {
	query := `
SELECT c.sbom_id, c.coordinate, c.license
FROM components c
WHERE c.sbom_id IN (` + placeholders(len(ids)) + `)
ORDER BY c.sbom_id ASC, c.coordinate ASC`
	args := int64Args(ids)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return unavailable(err)
	}
	defer rows.Close()

	for rows.Next() {
		var sbomID int64
		var comp model.Component
		comp.Dependencies = []string{}
		if err := rows.Scan(&sbomID, &comp.Coordinate, &comp.License); err != nil {
			return unavailable(err)
		}
		items[indexByID[sbomID]].Components = append(items[indexByID[sbomID]].Components, comp)
	}
	return rowsError(rows.Err())
}

// loadDependenciesInto reads every dependency edge of the given manifests in
// one query. Both endpoints belong to the same manifest: the JOIN on sbom_id
// keeps edges scoped to the given manifests and also prevents a target row
// from another version ever matching when coordinates repeat across versions.
// Like loadComponentsInto it is shared by List (for a page) and by Register's
// idempotency/conflict check (through loadSBOM, for a single manifest).
func loadDependenciesInto(ctx context.Context, q queryer, items []*model.SBOM, ids []int64, indexByID map[int64]int) error {
	query := `
SELECT sc.sbom_id, sc.coordinate, tc.coordinate
FROM dependencies d
JOIN components sc ON sc.id = d.component_id
JOIN components tc ON tc.id = d.target_id AND tc.sbom_id = sc.sbom_id
WHERE sc.sbom_id IN (` + placeholders(len(ids)) + `)
ORDER BY sc.sbom_id ASC, sc.coordinate ASC, tc.coordinate ASC`
	rows, err := q.QueryContext(ctx, query, int64Args(ids)...)
	if err != nil {
		return unavailable(err)
	}
	defer rows.Close()

	// Coordinates are unique within a manifest, so a (sbom ID, coordinate) pair
	// locates the owning component even when two versions share a coordinate.
	coordinateIndex := make(map[int64]map[string]int, len(items))
	for _, sbom := range items {
		byCoordinate := make(map[string]int, len(sbom.Components))
		for j := range sbom.Components {
			byCoordinate[sbom.Components[j].Coordinate] = j
		}
		coordinateIndex[sbom.ID] = byCoordinate
	}

	for rows.Next() {
		var sbomID int64
		var from, to string
		if err := rows.Scan(&sbomID, &from, &to); err != nil {
			return unavailable(err)
		}
		comp := &items[indexByID[sbomID]].Components[coordinateIndex[sbomID][from]]
		comp.Dependencies = append(comp.Dependencies, to)
	}
	return rowsError(rows.Err())
}

// rowsError maps a drained cursor's terminal error without wrapping nil.
func rowsError(err error) error {
	if err == nil {
		return nil
	}
	return unavailable(err)
}

// placeholders builds "?,?,?" for an IN-list of n values.
func placeholders(n int) string {
	return strings.Repeat("?,", n-1) + "?"
}

func int64Args(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

// loadSBOM reconstructs a single stored manifest for Register's
// idempotency/conflict check. It reads the manifest row itself, then rebuilds
// components and dependencies through the same loaders List applies to a
// page, so the registration read path and the paged read path share one
// reconstruction rule by construction.
func loadSBOM(ctx context.Context, q queryer, id int64) (*model.SBOM, error) {
	sbom := &model.SBOM{ID: id, Components: []model.Component{}}
	if err := q.QueryRowContext(ctx,
		"SELECT artifact, version FROM sboms WHERE id = ?", id,
	).Scan(&sbom.Artifact, &sbom.Version); err != nil {
		return nil, unavailable(err)
	}

	// A one-manifest page: the shared loaders keep the component and
	// dependency ordering/scoping rules identical to List's paged reads.
	items := []*model.SBOM{sbom}
	ids := []int64{id}
	indexByID := map[int64]int{id: 0}
	if err := loadComponentsInto(ctx, q, items, ids, indexByID); err != nil {
		return nil, err
	}
	if err := loadDependenciesInto(ctx, q, items, ids, indexByID); err != nil {
		return nil, err
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
