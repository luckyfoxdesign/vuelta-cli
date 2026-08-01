// Package history owns Vuelta's machine-local durable SQLite state.
//
// The database contains structured, bounded metadata only. Project contents,
// command output, environment values, credentials, and message bodies do not
// belong in this package. Narrow delivery IDs and cursors are persisted so an
// external bridge can recover idempotently without owning operation state.
package history
