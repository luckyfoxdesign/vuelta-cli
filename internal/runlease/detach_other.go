//go:build !unix

package runlease

import "os/exec"

func configureDetachedProcess(_ *exec.Cmd) {}
