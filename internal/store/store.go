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

// preparer is the transaction surface a write callback gets: the loaders'
// queryer plus context-aware statement preparation for the batched detail
// inserts. *sql.Conn satisfies it.
type preparer interface {
	queryer
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// txMode selects how a managed transaction starts.
type txMode int

const (
	// txDeferred issues a plain BEGIN: a read transaction that pins one
	// committed snapshot for every SELECT inside it.
	txDeferred txMode = iota
	// txImmediate issues BEGIN IMMEDIATE, taking the writer lock up front.
	txImmediate
)

// withTx is the single transaction lifecycle rule of the service; Register and
// List both run their work through it, so the lifecycle is verifiable from one
// place instead of being maintained twice:
//
//  1. acquire a dedicated connection and return it to the pool on every exit
//     (deferred Conn.Close);
//  2. begin the transaction in the requested mode;
//  3. run fn against that connection;
//  4. COMMIT exactly once when fn succeeds; otherwise — including an early
//     business return such as model.ErrConflict — best-effort ROLLBACK.
//
// The error fn returns is passed through untouched, so sentinel business
// errors stay errors.Is-recognizable and a storage error keeps its original
// cause. A failure of COMMIT itself is mapped to model.ErrStorageUnavailable;
// a failure of the best-effort ROLLBACK is deliberately swallowed so it can
// never replace the already-determined business or storage error.
func (s *Store) withTx(ctx context.Context, mode txMode, fn func(q preparer) error) error {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return unavailable(err)
	}
	// Rule 1: the connection is always returned, on success, business error
	// and storage failure alike.
	defer c.Close()

	begin := "BEGIN"
	if mode == txImmediate {
		// BEGIN IMMEDIATE takes the writer lock up front, so two concurrent
		// registrations for the same artifact/version serialize and the loser
		// re-reads the winner's committed row instead of hitting the unique
		// constraint.
		begin = "BEGIN IMMEDIATE"
	}
	if _, err := c.ExecContext(ctx, begin); err != nil {
		return unavailable(err)
	}

	committed := false
	// Rule 4: any exit without a successful COMMIT rolls back. The cleanup is
	// best effort and its error is discarded on purpose.
	defer func() {
		if !committed {
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
	var result *model.SBOM
	createdResult := false
	txErr := s.withTx(ctx, txImmediate, func(q preparer) error {
		var existingID int64
		switch err := q.QueryRowContext(ctx,
			"SELECT id FROM sboms WHERE artifact = ? AND version = ?",
			in.Artifact, in.Version,
		).Scan(&existingID); {
		case err == nil:
			existing, err := loadSBOM(ctx, q, existingID)
			if err != nil {
				return err
			}
			if !equalContent(existing, in) {
				return model.ErrConflict
			}
			result = existing
			return nil
		case errors.Is(err, sql.ErrNoRows):
			// Continue and insert.
		default:
			return unavailable(err)
		}

		res, err := q.ExecContext(ctx,
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
		insertComponent, err := q.PrepareContext(ctx,
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
			insertDep, err := q.PrepareContext(ctx,
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
		result = &out
		createdResult = true
		return nil
	})
	if txErr != nil {
		return nil, false, txErr
	}
	return result, createdResult, nil
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
	txErr := s.withTx(ctx, txDeferred, func(q preparer) error {
		if err := q.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sboms WHERE artifact = ?", artifact,
		).Scan(&total); err != nil {
			return unavailable(err)
		}

		// The page's main records, their non-nil empty component
		// collections and the id→page-index ownership table all come from
		// the one shared scan rule Register's reload and Diff use too.
		batch, err := scanManifestRows(ctx, q,
			"SELECT id, artifact, version FROM sboms WHERE artifact = ? ORDER BY id ASC LIMIT ? OFFSET ?",
			artifact, pageSize, (page-1)*pageSize)
		if err != nil {
			return err
		}
		items = batch.items

		// Empty page (unknown artifact or a page past the last one): the count
		// was already read, and the two detail queries must not run with an
		// empty IN list. Total is still returned to the caller.
		if len(batch.ids) == 0 {
			return nil
		}
		return attachDetails(ctx, q, batch)
	})
	if txErr != nil {
		return nil, 0, txErr
	}
	return items, total, nil
}

// Diff loads two registered manifests of one artifact for comparison. Both
// manifests are reconstructed inside one deferred read transaction and so
// share one committed snapshot: the caller can never compare two versions
// read from different commits, and neither manifest can ever be a
// half-written registration because Register commits the sbom row and every
// component/dependency atomically. When fromVersion and toVersion are
// identical the manifest is read once and the same record fills both result
// slots. A missing version yields model.ErrNotFound — still just that one
// error when both versions are absent. Every other read failure becomes
// model.ErrStorageUnavailable with no partial result.
func (s *Store) Diff(ctx context.Context, artifact, fromVersion, toVersion string) (from, to *model.SBOM, err error) {
	var fromSBOM, toSBOM *model.SBOM
	txErr := s.withTx(ctx, txDeferred, func(q preparer) error {
		// The unique (artifact, version) constraint makes the IN-list return
		// at most one row per version; collapse equal versions to one slot so
		// a self-comparison reads its manifest only once.
		versions := []string{fromVersion, toVersion}
		if fromVersion == toVersion {
			versions = []string{fromVersion}
		}
		query := `
SELECT id, artifact, version FROM sboms
WHERE artifact = ? AND version IN (` + placeholders(len(versions)) + `)
ORDER BY id ASC`
		args := make([]any, 0, len(versions)+1)
		args = append(args, artifact)
		for _, version := range versions {
			args = append(args, version)
		}
		rows, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return unavailable(err)
		}
		defer rows.Close()

		batch, err := collectManifestRows(rows)
		if err != nil {
			return err
		}

		byVersion := make(map[string]*model.SBOM, len(batch.ids))
		for _, sbom := range batch.items {
			byVersion[sbom.Version] = sbom
		}

		// Existence is settled against this snapshot before any detail read;
		// a single not-found result is returned even when both versions miss.
		fromSBOM = byVersion[fromVersion]
		toSBOM = byVersion[toVersion]
		if fromSBOM == nil || toSBOM == nil {
			return model.ErrNotFound
		}

		// One batched read per detail table for both manifests (or the single
		// self-comparison manifest), through the same loaders List and
		// Register use, so components and direct dependency edges follow the
		// one reconstruction rule.
		return attachDetails(ctx, q, batch)
	})
	if txErr != nil {
		return nil, nil, txErr
	}
	return fromSBOM, toSBOM, nil
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

// manifestBatch is the shared shape of one read of sbom main records: the
// reconstructed manifests (each starting with a non-nil empty component
// collection), their database IDs and the map that attributes a detail row
// back to its manifest. Register's reload, List's page scan and Diff's
// paired-version scan all produce one, so main-record parsing, empty-slice
// initialization and detail ownership live in exactly one place.
type manifestBatch struct {
	items     []*model.SBOM
	ids       []int64
	indexByID map[int64]int
}

// scanManifestRows runs query, drains every main-record row through
// collectManifestRows and closes the cursor. It is the shared entry for a
// main-record scan (List's paged read and Diff's version read); the single
// manifest Register reloads by id keeps its point QueryRow path.
func scanManifestRows(ctx context.Context, q queryer, query string, args ...any) (manifestBatch, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return manifestBatch{}, unavailable(err)
	}
	defer rows.Close()
	return collectManifestRows(rows)
}

// collectManifestRows scans an open sbom cursor into a manifestBatch. Every
// manifest starts with a non-nil empty Components slice, and ownership of
// each row is recorded as it is appended, so an empty result comes back as
// a usable empty batch rather than a nil one.
func collectManifestRows(rows *sql.Rows) (manifestBatch, error) {
	batch := manifestBatch{
		items:     []*model.SBOM{},
		ids:       []int64{},
		indexByID: map[int64]int{},
	}
	for rows.Next() {
		sbom := &model.SBOM{Components: []model.Component{}}
		if err := rows.Scan(&sbom.ID, &sbom.Artifact, &sbom.Version); err != nil {
			return manifestBatch{}, unavailable(err)
		}
		batch.indexByID[sbom.ID] = len(batch.items)
		batch.ids = append(batch.ids, sbom.ID)
		batch.items = append(batch.items, sbom)
	}
	if err := rows.Err(); err != nil {
		return manifestBatch{}, unavailable(err)
	}
	return batch, nil
}

// attachDetails runs the two batched detail loaders for one manifestBatch in
// their fixed order. It is the single reconstruction tail of every read
// path: Register's idempotency/conflict reload, List's page and Diff's
// paired versions all attach components then dependency edges the same way.
func attachDetails(ctx context.Context, q queryer, batch manifestBatch) error {
	if err := loadComponentsInto(ctx, q, batch.items, batch.ids, batch.indexByID); err != nil {
		return err
	}
	return loadDependenciesInto(ctx, q, batch.items, batch.ids, batch.indexByID)
}

// loadSBOM reconstructs a single stored manifest for Register's
// idempotency/conflict check. It reads the manifest row itself, then rebuilds
// components and dependencies through the same attachDetails tail List and
// Diff apply, so the registration read path and the paged/paired read paths
// share one reconstruction rule by construction.
func loadSBOM(ctx context.Context, q queryer, id int64) (*model.SBOM, error) {
	sbom := &model.SBOM{ID: id, Components: []model.Component{}}
	if err := q.QueryRowContext(ctx,
		"SELECT artifact, version FROM sboms WHERE id = ?", id,
	).Scan(&sbom.Artifact, &sbom.Version); err != nil {
		return nil, unavailable(err)
	}

	// A one-manifest batch hands the single record straight to the shared
	// detail loaders without a second sbom SELECT.
	if err := attachDetails(ctx, q, manifestBatch{
		items:     []*model.SBOM{sbom},
		ids:       []int64{id},
		indexByID: map[int64]int{id: 0},
	}); err != nil {
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
