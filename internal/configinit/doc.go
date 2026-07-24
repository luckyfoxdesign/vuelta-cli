// Package configinit creates protected config containers, guards unsafe roots,
// deterministically detects a selected project's supported files without
// requiring Git, and applies atomic reviewed edits. It never walks parent
// directories or reads unallowlisted files.
package configinit
