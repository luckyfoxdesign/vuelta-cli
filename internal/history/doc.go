// Package history owns Vuelta's machine-local durable SQLite state.
//
// The database contains structured, bounded metadata only. Project contents,
// command output, environment values, credentials, and transport-specific
// notification state do not belong in this package.
package history
