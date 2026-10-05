package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sqlite3 "modernc.org/sqlite"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

func TestOpenCreatesUsableStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// --- SELECT counting through a wrapped database/sql/driver ------------------
//
// The counter sits below database/sql, on the actual driver connection, so it
// observes the SQL statements the store really sends. It cannot be satisfied by
// an internal function being called or by cached results.

type selectCall struct {
	query string
	args  []any
}

type queryCounter struct {
	mu      sync.Mutex
	selects []selectCall
	// failAt, when positive, is the 1-based ordinal of a SELECT that must
	// return an injected driver error instead of reaching SQLite.
	failAt int
}

// record appends a SELECT observation and returns its 1-based ordinal.
func (q *queryCounter) record(query string, args []driver.NamedValue) int {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT") {
		return 0
	}
	values := make([]any, len(args))
	for i, arg := range args {
		values[i] = arg.Value
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.selects = append(q.selects, selectCall{query: query, args: values})
	return len(q.selects)
}

func (q *queryCounter) reset() {
	q.mu.Lock()
	q.selects = nil
	q.failAt = 0
	q.mu.Unlock()
}

func (q *queryCounter) setFailure(ordinal int) {
	q.mu.Lock()
	q.failAt = ordinal
	q.mu.Unlock()
}

func (q *queryCounter) shouldFail(ordinal int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return ordinal > 0 && q.failAt == ordinal
}

func (q *queryCounter) calls() []selectCall {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]selectCall, len(q.selects))
	copy(out, q.selects)
	return out
}

// dsnConnector opens fresh driver connections for a fixed DSN.
type dsnConnector struct {
	drv driver.Driver
	dsn string
}

func (c dsnConnector) Connect(context.Context) (driver.Conn, error) { return c.drv.Open(c.dsn) }
func (c dsnConnector) Driver() driver.Driver                        { return c.drv }

type countingConnector struct {
	inner driver.Connector
	qc    *queryCounter
}

func (c countingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, qc: c.qc}, nil
}

func (c countingConnector) Driver() driver.Driver { return c.inner.Driver() }

// countingConn only intercepts the context query/exec entry points the store
// uses; transaction control and everything else pass through unchanged.
type countingConn struct {
	driver.Conn
	qc *queryCounter
}

func (c *countingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if pc, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return pc.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func (c *countingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.qc.record(query, args)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	ordinal := c.qc.record(query, args)
	if c.qc.shouldFail(ordinal) {
		return nil, errInjectedRead
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

// errInjectedRead stands in for a real storage failure reported by the driver.
var errInjectedRead = errors.New("injected read failure")

func (c *countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *countingConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

// openCountingStore returns a store whose driver traffic runs through a fresh
// counter. The schema and WAL mode are provisioned normally first, so the
// counting connection opens an existing, already-migrated database file.
func openCountingStore(t *testing.T) (*Store, *queryCounter) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "counting.db")
	boot, err := Open(path)
	if err != nil {
		t.Fatalf("bootstrap open: %v", err)
	}
	if err := boot.Close(); err != nil {
		t.Fatalf("bootstrap close: %v", err)
	}

	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	qc := &queryCounter{}
	db := sql.OpenDB(countingConnector{
		inner: dsnConnector{drv: &sqlite3.Driver{}, dsn: dsn},
		qc:    qc,
	})
	t.Cleanup(func() { db.Close() })
	return &Store{db: db}, qc
}

func registerManifest(t *testing.T, st *Store, artifact, version string, components ...model.Component) int64 {
	t.Helper()
	if components == nil {
		components = []model.Component{}
	}
	sbom, _, err := st.Register(context.Background(), &model.SBOM{
		Artifact:   artifact,
		Version:    version,
		Components: components,
	})
	if err != nil {
		t.Fatalf("register %s/%s: %v", artifact, version, err)
	}
	return sbom.ID
}

func twoComponentManifest(license string) []model.Component {
	return []model.Component{
		{Coordinate: "core", License: license, Dependencies: []string{"util"}},
		{Coordinate: "util", License: "license-for-util", Dependencies: []string{}},
	}
}

func assertSelectsAtMost(t *testing.T, calls []selectCall, limit int) {
	t.Helper()
	if len(calls) > limit {
		queries := make([]string, len(calls))
		for i, call := range calls {
			queries[i] = strings.Join(strings.Fields(call.query), " ")
		}
		t.Fatalf("SELECT count = %d, want at most %d; statements:\n%s", len(calls), limit, strings.Join(queries, "\n"))
	}
}

func TestListRunsAtMostFourSelects(t *testing.T) {
	st, qc := openCountingStore(t)
	ctx := context.Background()

	t.Run("one manifest", func(t *testing.T) {
		registerManifest(t, st, "solo", "1", twoComponentManifest("L1")...)
		qc.reset()
		items, total, err := st.List(ctx, "solo", 1, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 1 || len(items) != 1 {
			t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
		}
		calls := qc.calls()
		if len(calls) != 4 {
			t.Fatalf("SELECTs for one manifest = %d, want exactly 4", len(calls))
		}
		assertSelectsAtMost(t, calls, 4)
	})

	t.Run("one hundred manifests", func(t *testing.T) {
		// 100 manifests for the paged artifact, each carrying two components
		// and one dependency edge, plus manifests for another artifact whose
		// details must never enter the page queries.
		const n = 100
		wantIDs := make([]any, 0, n)
		for i := 0; i < n; i++ {
			id := registerManifest(t, st, "bulk", fmt.Sprintf("v%03d", i),
				twoComponentManifest(fmt.Sprintf("license-v%03d", i))...)
			wantIDs = append(wantIDs, id)
		}
		for _, v := range []string{"o1", "o2", "o3"} {
			registerManifest(t, st, "other", v,
				model.Component{Coordinate: "intruder", License: "X", Dependencies: []string{}})
		}

		qc.reset()
		items, total, err := st.List(ctx, "bulk", 1, n)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != n || len(items) != n {
			t.Fatalf("total/items = %d/%d, want %d/%d", total, len(items), n, n)
		}
		calls := qc.calls()
		if len(calls) != 4 {
			t.Fatalf("SELECTs with a full, non-empty page = %d, want exactly 4", len(calls))
		}

		// The two detail statements must bind exactly the current page's ids,
		// in ascending order: nothing from other pages or other artifacts.
		componentArgs := calls[2].args
		dependencyArgs := calls[3].args
		if len(componentArgs) != n || len(dependencyArgs) != n {
			t.Fatalf("detail bound args = %d/%d, want %d each", len(componentArgs), len(dependencyArgs), n)
		}
		for i, want := range wantIDs {
			if componentArgs[i] != want || dependencyArgs[i] != want {
				t.Fatalf("detail query bound %v/%v at position %d, want page id %v",
					componentArgs[i], dependencyArgs[i], i, want)
			}
		}
	})

	t.Run("detail scope is the current page only", func(t *testing.T) {
		qc.reset()
		items, total, err := st.List(ctx, "bulk", 2, 50)
		if err != nil {
			t.Fatalf("list page 2: %v", err)
		}
		if total != 100 || len(items) != 50 {
			t.Fatalf("total/items = %d/%d, want 100/50", total, len(items))
		}
		calls := qc.calls()
		if len(calls) != 4 {
			t.Fatalf("SELECTs = %d, want 4", len(calls))
		}
		scoped := calls[2].args
		if len(scoped) != 50 {
			t.Fatalf("component SELECT bound %d ids, want 50", len(scoped))
		}
		pageIDs := make(map[int64]struct{}, 50)
		for _, sbom := range items {
			pageIDs[sbom.ID] = struct{}{}
		}
		for _, arg := range scoped {
			id, ok := arg.(int64)
			if !ok {
				t.Fatalf("bound arg %v is not int64", arg)
			}
			if _, onPage := pageIDs[id]; !onPage {
				t.Fatalf("detail SELECT loads sbom id %d which is not on the current page", id)
			}
		}
	})

	t.Run("empty pages skip detail reads", func(t *testing.T) {
		qc.reset()
		items, total, err := st.List(ctx, "ghost", 1, 20)
		if err != nil {
			t.Fatalf("list unknown: %v", err)
		}
		if total != 0 || len(items) != 0 {
			t.Fatalf("unknown artifact total/items = %d/%d", total, len(items))
		}
		if items == nil {
			t.Fatalf("items is nil, want empty slice")
		}
		if n := len(qc.calls()); n != 2 {
			t.Fatalf("unknown artifact SELECTs = %d, want 2 (count + page)", n)
		}

		qc.reset()
		items, total, err = st.List(ctx, "bulk", 3, 50)
		if err != nil {
			t.Fatalf("list past end: %v", err)
		}
		if total != 100 || len(items) != 0 {
			t.Fatalf("past-end total/items = %d/%d, want 100/0", total, len(items))
		}
		if items == nil {
			t.Fatalf("past-end items is nil, want empty slice")
		}
		if n := len(qc.calls()); n != 2 {
			t.Fatalf("past-end SELECTs = %d, want 2", n)
		}
	})
}

func TestListKeepsSameCoordinatesIsolatedAcrossVersions(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	// Both versions contain a component at the identical coordinate, but with
	// a different license and a different dependency target.
	registerManifest(t, st, "app", "v1",
		model.Component{Coordinate: "a", License: "license-in-v1", Dependencies: []string{"shared"}},
		model.Component{Coordinate: "shared", License: "shared-license-v1", Dependencies: []string{"a"}},
	)
	registerManifest(t, st, "app", "v2",
		model.Component{Coordinate: "b", License: "license-in-v2", Dependencies: []string{"shared"}},
		model.Component{Coordinate: "shared", License: "shared-license-v2", Dependencies: []string{"b"}},
	)
	// A legal dependency cycle must come back complete.
	registerManifest(t, st, "app", "v3",
		model.Component{Coordinate: "x", License: "L", Dependencies: []string{"y"}},
		model.Component{Coordinate: "y", License: "L", Dependencies: []string{"x"}},
	)
	// An entirely empty manifest.
	registerManifest(t, st, "app", "v4")

	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 4 || len(items) != 4 {
		t.Fatalf("total/items = %d/%d, want 4/4", total, len(items))
	}

	v1 := findByVersion(t, items, "v1")
	v2 := findByVersion(t, items, "v2")
	v3 := findByVersion(t, items, "v3")
	v4 := findByVersion(t, items, "v4")

	shared1 := componentByName(t, v1, "shared")
	if shared1.License != "shared-license-v1" {
		t.Fatalf("v1 shared license = %q, want shared-license-v1", shared1.License)
	}
	if len(shared1.Dependencies) != 1 || shared1.Dependencies[0] != "a" {
		t.Fatalf("v1 shared dependencies = %v, want [a]", shared1.Dependencies)
	}
	if deps := componentByName(t, v1, "a").Dependencies; len(deps) != 1 || deps[0] != "shared" {
		t.Fatalf("v1 a dependencies = %v, want [shared]", deps)
	}

	shared2 := componentByName(t, v2, "shared")
	if shared2.License != "shared-license-v2" {
		t.Fatalf("v2 shared license = %q, want shared-license-v2", shared2.License)
	}
	if len(shared2.Dependencies) != 1 || shared2.Dependencies[0] != "b" {
		t.Fatalf("v2 shared dependencies = %v, want [b]", shared2.Dependencies)
	}

	x := componentByName(t, v3, "x")
	y := componentByName(t, v3, "y")
	if len(x.Dependencies) != 1 || x.Dependencies[0] != "y" ||
		len(y.Dependencies) != 1 || y.Dependencies[0] != "x" {
		t.Fatalf("cycle incompletely read: x -> %v, y -> %v", x.Dependencies, y.Dependencies)
	}

	// Empty components come back as an array; a component without dependency
	// edges still carries an empty (non-nil) array.
	if v4.Components == nil || len(v4.Components) != 0 {
		t.Fatalf("v4 components = %v, want empty non-nil array", v4.Components)
	}
	if componentByName(t, v1, "a").Dependencies == nil {
		t.Fatalf("component dependencies slice is nil, want empty array")
	}
}

func TestListOrdersItemsComponentsAndDependencies(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()
	// Register versions deliberately out of order.
	for _, version := range []string{"v3", "v1", "v2"} {
		registerManifest(t, st, "ord", version,
			model.Component{Coordinate: "zeta", License: "L", Dependencies: []string{"alpha", "mid"}},
			model.Component{Coordinate: "alpha", License: "L", Dependencies: []string{}},
			model.Component{Coordinate: "mid", License: "L", Dependencies: []string{"alpha"}},
		)
	}
	items, _, err := st.List(ctx, "ord", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var previous int64
	for _, item := range items {
		if item.ID < previous {
			t.Fatalf("items not id-ascending: %d follows %d", item.ID, previous)
		}
		previous = item.ID
		for i := 1; i < len(item.Components); i++ {
			if item.Components[i-1].Coordinate >= item.Components[i].Coordinate {
				t.Fatalf("components not coordinate-ordered: %v", item.Components)
			}
		}
		zeta := componentByName(t, item, "zeta")
		if len(zeta.Dependencies) != 2 || zeta.Dependencies[0] != "alpha" || zeta.Dependencies[1] != "mid" {
			t.Fatalf("dependencies not coordinate-ordered: %v", zeta.Dependencies)
		}
	}
}

func TestListStorageFailureIsUnavailableWithoutPartialItems(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "v1", twoComponentManifest("L1")...)
	if err := st.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	items, total, err := st.List(context.Background(), "app", 1, 20)
	if !errors.Is(err, model.ErrStorageUnavailable) {
		t.Fatalf("err = %v, want ErrStorageUnavailable", err)
	}
	if items != nil || total != 0 {
		t.Fatalf("items/total = %v/%d, want nil/0 on failure", items, total)
	}
}

// TestListFailsDeterministicallyAtEveryReadStep injects a driver error at each
// of the four SELECTs in turn. Every read step failing must surface the same
// storage sentinel with no partial items and no stale total.
func TestListFailsDeterministicallyAtEveryReadStep(t *testing.T) {
	st, qc := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "v1", twoComponentManifest("L1")...)
	registerManifest(t, st, "app", "v2", twoComponentManifest("L2")...)

	for step := 1; step <= 4; step++ {
		t.Run(fmt.Sprintf("select-%d-fails", step), func(t *testing.T) {
			qc.reset()
			qc.setFailure(step)
			t.Cleanup(func() { qc.setFailure(0) })

			items, total, err := st.List(ctx, "app", 1, 20)
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("step %d err = %v, want ErrStorageUnavailable", step, err)
			}
			if items != nil {
				t.Fatalf("step %d returned partial items: %+v", step, items)
			}
			if total != 0 {
				t.Fatalf("step %d returned total %d, want 0", step, total)
			}
			if observed := len(qc.calls()); observed != step {
				t.Fatalf("step %d executed %d SELECTs before failing, want exactly %d", step, observed, step)
			}
		})
	}

	// With the fault cleared, the same page reads completely: no caching is
	// hiding the earlier failures.
	qc.reset()
	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list after fault cleared: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total/items = %d/%d, want 2/2", total, len(items))
	}
}

// TestListReadsOneCommittedSnapshot holds a partially written manifest in an
// open write transaction and asserts the reader sees neither the sbom row nor
// any of its half-written detail; after commit the complete manifest appears.
func TestListReadsOneCommittedSnapshot(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "committed", twoComponentManifest("L0")...)

	conn, err := st.db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	res, err := tx.ExecContext(ctx, "INSERT INTO sboms (artifact, version) VALUES ('app', 'in-flight')")
	if err != nil {
		t.Fatalf("insert sbom: %v", err)
	}
	inFlightID, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO components (sbom_id, coordinate, license) VALUES (?, 'partial', 'L?')", inFlightID); err != nil {
		t.Fatalf("insert partial component: %v", err)
	}

	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list during open write tx: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("reader observed uncommitted data: total=%d items=%d", total, len(items))
	}
	if items[0].Version != "committed" {
		t.Fatalf("reader returned uncommitted manifest %q", items[0].Version)
	}
	for _, comp := range items[0].Components {
		if comp.Coordinate == "partial" {
			t.Fatalf("reader observed an uncommitted component")
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	items, total, err = st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list after commit: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("post-commit total/items = %d/%d, want 2/2", total, len(items))
	}
	if items[1].Version != "in-flight" || len(items[1].Components) != 1 {
		t.Fatalf("post-commit manifest incomplete: %+v", items[1])
	}
}

func findByVersion(t *testing.T, items []*model.SBOM, version string) *model.SBOM {
	t.Helper()
	for _, item := range items {
		if item.Version == version {
			return item
		}
	}
	t.Fatalf("manifest %s not found", version)
	return nil
}

func componentByName(t *testing.T, sbom *model.SBOM, coordinate string) model.Component {
	t.Helper()
	for _, comp := range sbom.Components {
		if comp.Coordinate == coordinate {
			return comp
		}
	}
	t.Fatalf("component %s not found in manifest %s", coordinate, sbom.Version)
	return model.Component{}
}
