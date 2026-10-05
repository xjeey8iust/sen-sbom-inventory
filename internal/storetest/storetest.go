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
	// failWriteKind, when non-empty, makes the next INSERT of that kind
	// ("sboms"/"components"/"dependencies") fail, whether it is issued
	// directly or through a prepared statement.
	failWriteKind string
	// failRollback makes the next ROLLBACK report failure.
	failRollback bool
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

// Reset clears the observed counters and every pending fault.
func (d *Driver) Reset() {
	d.mu.Lock()
	d.stats.selects = 0
	d.stats.rowsByKind = map[string]int{}
	d.failKind = ""
	d.failWriteKind = ""
	d.failRollback = false
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

// FailNextWrite makes the next INSERT of kind
// ("sboms"/"components"/"dependencies") fail, simulating a storage write
// error during one detail-write step of a registration.
func (d *Driver) FailNextWrite(kind string) {
	d.mu.Lock()
	d.failWriteKind = kind
	d.mu.Unlock()
}

// FailNextRollback makes the next ROLLBACK statement report failure, so tests
// can prove transaction-cleanup errors never overwrite the error that
// triggered the rollback.
func (d *Driver) FailNextRollback() {
	d.mu.Lock()
	d.failRollback = true
	d.mu.Unlock()
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
	if isRollback(query) {
		// Always run the real ROLLBACK first: the connection must actually
		// leave its transaction before going back to the pool. The synthetic
		// failure only reports what the store must learn to ignore.
		res, err := c.Conn.(driver.Execer).Exec(query, args)
		c.driver.mu.Lock()
		fail := c.driver.failRollback
		c.driver.failRollback = false
		c.driver.mu.Unlock()
		if fail {
			return res, errors.New("forced rollback failure from test driver")
		}
		return res, err
	}
	if err := c.checkExecFault(query); err != nil {
		return nil, err
	}
	return c.Conn.(driver.Execer).Exec(query, args)
}

// Prepare wraps prepared statements too: the store batches the component and
// dependency inserts through a prepared statement, so a write fault has to be
// visible on that path and not only for direct Exec calls.
func (c *countingConn) Prepare(query string) (driver.Stmt, error) {
	raw, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &countingStmt{Stmt: raw, driver: c.driver, query: query}, nil
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
		if fail {
			// A one-shot fault: consume it so only the next matching read fails.
			c.driver.failKind = ""
		}
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

// checkExecFault consumes any pending write fault for the statement and
// returns the synthetic error when one fires. Callers must route ROLLBACK
// elsewhere: that path runs the real rollback before reporting its synthetic
// failure so a pooled connection never stays inside an open transaction.
func (c *countingConn) checkExecFault(query string) error {
	if kind := WriteKind(query); kind != "" {
		c.driver.mu.Lock()
		fire := c.driver.failWriteKind == kind
		if fire {
			c.driver.failWriteKind = ""
		}
		c.driver.mu.Unlock()
		if fire {
			return errors.New("forced write failure from test driver")
		}
	}
	return nil
}

// countingStmt carries the originating query so the fault configured for that
// statement's table fires on Exec.
type countingStmt struct {
	driver.Stmt
	driver *Driver
	query  string
}

func (s *countingStmt) Exec(args []driver.Value) (driver.Result, error) {
	if kind := WriteKind(s.query); kind != "" {
		s.driver.mu.Lock()
		fire := s.driver.failWriteKind == kind
		if fire {
			s.driver.failWriteKind = ""
		}
		s.driver.mu.Unlock()
		if fire {
			return nil, errors.New("forced write failure from test driver")
		}
	}
	return s.Stmt.Exec(args)
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

// WriteKind classifies the store's INSERT statements so tests can target one
// detail-write step: "sboms", "components" or "dependencies". Every other
// statement returns the empty string.
func WriteKind(query string) string {
	s := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(s, "INSERT INTO") {
		return ""
	}
	switch {
	case strings.HasPrefix(s, "INSERT INTO COMPONENTS"):
		return "components"
	case strings.HasPrefix(s, "INSERT INTO DEPENDENCIES"):
		return "dependencies"
	default:
		return "sboms"
	}
}

func isRollback(query string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "ROLLBACK")
}
