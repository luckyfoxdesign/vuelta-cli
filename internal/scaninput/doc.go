// Package scaninput validates and archives only exact files declared by an
// ecosystem adapter or a core Docker/policy stage. It never discovers files
// and denies secret-like inputs unless a reviewed adapter config explicitly
// opts in.
package scaninput
