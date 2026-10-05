// Package storetest provides test infrastructure for the SBOM service: a
// database/sql driver that wraps the real SQLite driver and counts the
// statements a request actually issues, optionally forcing read failures.
// It wraps the genuine driver end to end rather than mocking internals.
package storetest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"

	sqlitedriver "modernc.org/sqlite"
)

// Counters summarizes the SELECTs observed by the counting driver.
type Counters struct {
	// Selects is the total number of SELECT statements executed.
	Selects int
	// RowsByKind is the number of result rows returned, keyed by statement
	// kind: "count", "sboms", "components", "dependencies".
	RowsByKind map[string]int
}

// Driver is a database/sql/driver.Driver wrapping the genuine SQLite driver.
// A single registration is shared by every connection, so counters cover a
// whole request even when database/sql reuses pooled connections.
type Driver struct {
	inner driver.Driver
	mu    sync.Mutex
	stats struct {
		selects    int
		rowsByKind map[string]int
	}
	// failKind, when non-empty, makes the next SELECT of that kind fail.
	failKind string
	// failWriteKind, when non-empty, makes INSERTs of that kind fail.
	failWriteKind string
}

// DriverName is the database/sql name under which the counting driver is
// registered.
const DriverName = "sqlite-counttest"

var (
	once   sync.Once
	shared *Driver
)

// Register registers the shared counting driver once and returns it,
// resetting its counters. Each test package runs in its own binary, so the
// fixed name does not collide across packages.
func Register() *Driver {
	once.Do(func() {
		shared = &Driver{inner: &sqlitedriver.Driver{}}
		sql.Register(DriverName, shared)
	})
	shared.Reset()
	return shared
}

// Reset clears the observed counters and any pending fault.
func (d *Driver) Reset() {
	d.mu.Lock()
	d.stats.selects = 0
	d.stats.rowsByKind = map[string]int{}
	d.failKind = ""
	d.failWriteKind = ""
	d.mu.Unlock()
}

// FailNextRead makes the next SELECT of kind
// ("count"/"sboms"/"components"/"dependencies") fail at the driver,
// simulating a storage read error.
func (d *Driver) FailNextRead(kind string) {
	d.mu.Lock()
	d.failKind = kind
	d.mu.Unlock()
}

// FailNextWrite makes INSERTs into the given table
// ("sboms"/"components"/"dependencies") fail at the driver, simulating a
// storage write error. The fault stays armed until Reset, whether the
// statement runs through a direct Exec or a prepared statement.
func (d *Driver) FailNextWrite(kind string) {
	d.mu.Lock()
	d.failWriteKind = kind
	d.mu.Unlock()
}

// writeFaultPending reports whether an INSERT of the given kind must fail.
func (d *Driver) writeFaultPending(kind string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return kind != "" && d.failWriteKind == kind
}

// Snapshot returns a point-in-time copy of the counters.
func (d *Driver) Snapshot() Counters {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows := make(map[string]int, len(d.stats.rowsByKind))
	for k, v := range d.stats.rowsByKind {
		rows[k] = v
	}
	return Counters{Selects: d.stats.selects, RowsByKind: rows}
}

func (d *Driver) Open(name string) (driver.Conn, error) {
	raw, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: raw, driver: d}, nil
}

// countingConn exposes the same legacy driver.Execer/driver.Queryer surface
// database/sql uses with the modernc driver; statements flow through Exec and
// Query where the counter lives.
type countingConn struct {
	driver.Conn
	driver *Driver
}

func (c *countingConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	if c.driver.writeFaultPending(WriteKind(query)) {
		return nil, errors.New("forced write failure from test driver")
	}
	return c.Conn.(driver.Execer).Exec(query, args)
}

// Prepare wraps the inner statement so INSERTs issued through prepared
// statements (the store's component and dependency detail writes) observe the
// same injected write faults as direct Exec calls.
func (c *countingConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &countingStmt{Stmt: stmt, driver: c.driver, kind: WriteKind(query)}, nil
}

// countingStmt intercepts Exec on prepared INSERT statements.
type countingStmt struct {
	driver.Stmt
	driver *Driver
	kind   string
}

func (s *countingStmt) Exec(args []driver.Value) (driver.Result, error) {
	if s.driver.writeFaultPending(s.kind) {
		return nil, errors.New("forced write failure from test driver")
	}
	return s.Stmt.Exec(args)
}

// ResetSession and IsValid delegate the optional driver interfaces so pooled
// connections behave under the wrapper exactly as with the raw driver.
func (c *countingConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *countingConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

func (c *countingConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	kind := SelectKind(query)
	if kind != "" {
		c.driver.mu.Lock()
		fail := c.driver.failKind == kind
		c.driver.mu.Unlock()
		if fail {
			return nil, errors.New("forced read failure from test driver")
		}
	}
	rows, err := c.Conn.(driver.Queryer).Query(query, args)
	if err != nil || kind == "" {
		return rows, err
	}
	c.driver.mu.Lock()
	c.driver.stats.selects++
	c.driver.mu.Unlock()
	return &countingRows{Rows: rows, driver: c.driver, kind: kind}, nil
}

type countingRows struct {
	driver.Rows
	driver *Driver
	kind   string
}

func (r *countingRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		r.driver.mu.Lock()
		r.driver.stats.rowsByKind[r.kind]++
		r.driver.mu.Unlock()
	}
	return err
}

// SelectKind classifies the store's read statements. Transaction control, DDL
// and PRAGMAs return the empty string and are never counted.
func SelectKind(query string) string {
	s := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(s, "SELECT") {
		return ""
	}
	switch {
	case strings.Contains(s, "COUNT(*)"):
		return "count"
	case strings.Contains(s, "FROM COMPONENTS C"):
		return "components"
	case strings.Contains(s, "FROM DEPENDENCIES D"):
		return "dependencies"
	default:
		return "sboms"
	}
}

// WriteKind classifies the store's INSERT statements by target table;
// anything else returns the empty string.
func WriteKind(query string) string {
	s := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(s, "INSERT") {
		return ""
	}
	switch {
	case strings.Contains(s, "INTO COMPONENTS"):
		return "components"
	case strings.Contains(s, "INTO DEPENDENCIES"):
		return "dependencies"
	default:
		return "sboms"
	}
}
