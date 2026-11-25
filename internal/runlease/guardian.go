package runlease

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

const cleanShutdownMarker = "clean\n"

// Guardian keeps a pipe open to a detached cleanup process. An abrupt parent
// exit closes the pipe without the clean marker, causing resource cleanup.
type Guardian struct {
	pipe     *os.File
	wait     <-chan error
	finishMu sync.Mutex
	finished bool
}

// StartGuardian starts the hidden Vuelta cleanup process.
func StartGuardian(executable, configPath, dockerPath, invocation, socket string) (*Guardian, error) {
	if !ValidID(invocation) {
		return nil, errors.New("invalid cleanup guardian invocation identity")
	}
	for _, value := range []string{executable, configPath, dockerPath, socket} {
		if !filepath.IsAbs(value) {
			return nil, errors.New("cleanup guardian paths must be absolute")
		}
	}
	command := exec.Command(
		executable,
		"__vuelta-cleanup-guardian",
		"--config", configPath,
		"--docker", dockerPath,
		"--socket", socket,
		"--invocation", invocation,
	)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/local/bin"}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return startGuardianCommand(command)
}

func startGuardianCommand(command *exec.Cmd) (*Guardian, error) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, errors.New("create cleanup guardian pipe")
	}
	command.ExtraFiles = []*os.File{readPipe}
	configureDetachedProcess(command)
	if err := command.Start(); err != nil {
		_ = readPipe.Close()
		_ = writePipe.Close()
		return nil, errors.New("start cleanup guardian")
	}
	if err := readPipe.Close(); err != nil {
		_ = writePipe.Close()
		return nil, errors.New("close parent cleanup guardian reader")
	}
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(wait)
	}()
	return &Guardian{pipe: writePipe, wait: wait}, nil
}

// Finish closes the parent lease and waits for the guardian. clean tells the
// guardian that normal in-process cleanup completed; otherwise it performs
// label-scoped cleanup before exiting.
func (g *Guardian) Finish(ctx context.Context, clean bool) error {
	if g == nil {
		return nil
	}
	g.finishMu.Lock()
	if g.finished {
		g.finishMu.Unlock()
		return nil
	}
	g.finished = true
	if clean {
		_, _ = io.WriteString(g.pipe, cleanShutdownMarker)
	}
	closeErr := g.pipe.Close()
	g.finishMu.Unlock()

	select {
	case waitErr := <-g.wait:
		return errors.Join(closeErr, waitErr)
	case <-ctx.Done():
		return errors.Join(closeErr, ctx.Err())
	}
}

// WaitForParent reports whether the parent disappeared without completing its
// normal cleanup protocol.
func WaitForParent(reader io.Reader) (bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(len(cleanShutdownMarker)+1)))
	if err != nil {
		return false, errors.New("read cleanup guardian pipe")
	}
	return string(data) != cleanShutdownMarker, nil
}
