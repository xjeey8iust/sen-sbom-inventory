package store

// This file exposes test-only construction hooks. The package lives under
// internal/, so nothing outside this module can depend on them; production
// callers continue to use Open.

// OpenWithDriver opens a Store through a registered database/sql driver name.
// It exists so tests can wrap the real SQLite driver with a counting or
// fault-injecting driver.
func OpenWithDriver(path, driverName string) (*Store, error) {
	return open(path, driverName)
}
