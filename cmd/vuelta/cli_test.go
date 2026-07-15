package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTopLevelHelpGolden(t *testing.T) {
	stdout, _, command := testCLI(nil)
	if err := command.run(nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	assertGolden(t, "top-level-help.golden", stdout.String())
	if strings.Contains(stdout.String(), "\n  project ") || strings.Contains(stdout.String(), "\n  update ") {
		t.Fatal("top-level help advertises a command that is not executable yet")
	}
}

func TestCommandHelpAliasesAreEquivalent(t *testing.T) {
	shortOutput, _, shortCommand := testCLI(nil)
	if err := shortCommand.run([]string{"config", "init", "-h"}); err != nil {
		t.Fatalf("short help: %v", err)
	}
	longOutput, _, longCommand := testCLI(nil)
	if err := longCommand.run([]string{"config", "init", "--help"}); err != nil {
		t.Fatalf("long help: %v", err)
	}
	if shortOutput.String() != longOutput.String() {
		t.Fatal("-h and --help produced different output")
	}
	assertGolden(t, "config-init-help.golden", shortOutput.String())
}

func TestHelpDoesNotExecuteCommand(t *testing.T) {
	stdout, _, command := testCLI(nil)
	missingConfig := filepath.Join(t.TempDir(), "missing.yaml")
	if err := command.run([]string{"scan", "--config", missingConfig, "--help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "vuelta scan —") {
		t.Fatalf("stdout = %q, want scan help", stdout.String())
	}
}

func TestUnknownCommandSuggestsWithoutExecuting(t *testing.T) {
	_, _, command := testCLI(nil)
	err := command.run([]string{"scna"})
	if err == nil {
		t.Fatal("unknown command succeeded")
	}
	if !strings.Contains(err.Error(), `Did you mean "scan"?`) {
		t.Fatalf("error = %q, want scan suggestion", err)
	}
	var coded commandError
	if !errorsAs(err, &coded) || coded.code != exitConfig {
		t.Fatalf("error = %#v, want exit code %d", err, exitConfig)
	}
}

func TestUnknownOptionGolden(t *testing.T) {
	_, _, command := testCLI(nil)
	err := command.run([]string{"scan", "--porject", "api"})
	if err == nil {
		t.Fatal("unknown option succeeded")
	}
	assertGolden(t, "unknown-option.golden", err.Error()+"\n")
}

func TestVersionWorksBeforeOrAfterCommand(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"scan", "--version"}} {
		stdout, _, command := testCLI(nil)
		if err := command.run(args); err != nil {
			t.Fatalf("run %v: %v", args, err)
		}
		if got, want := stdout.String(), "vuelta dev\n"; got != want {
			t.Fatalf("run %v output = %q, want %q", args, got, want)
		}
	}
}

func TestGlobalOptionPlacementAndTerminator(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		config    string
		remaining []string
	}{
		{name: "before command", args: []string{"--config", "one.yaml", "scan"}, config: "one.yaml", remaining: []string{"scan"}},
		{name: "after command", args: []string{"scan", "-c", "two.yaml"}, config: "two.yaml", remaining: []string{"scan"}},
		{name: "equals", args: []string{"scan", "--config=three.yaml"}, config: "three.yaml", remaining: []string{"scan"}},
		{name: "terminator", args: []string{"scan", "--", "--config", "literal"}, remaining: []string{"scan", "--", "--config", "literal"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, remaining, err := parseGlobalOptions(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if options.config != test.config || !reflect.DeepEqual(remaining, test.remaining) {
				t.Fatalf("config, remaining = %q, %v; want %q, %v", options.config, remaining, test.config, test.remaining)
			}
		})
	}
}

func TestParserSupportsInterspersedFlagsAndTerminator(t *testing.T) {
	definition := commandDefinition{
		path: []string{"update"},
		options: []optionDefinition{
			{names: []string{"--dry-run"}},
			{names: []string{"--name"}, valueName: "NAME"},
		},
	}
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "flag before positional", args: []string{"--dry-run", "abc123"}, want: []string{"--dry-run", "abc123"}},
		{name: "flag after positional", args: []string{"abc123", "--dry-run"}, want: []string{"--dry-run", "abc123"}},
		{name: "value flag after positional", args: []string{"./api", "--name", "api"}, want: []string{"--name", "api", "./api"}},
		{name: "terminator", args: []string{"abc123", "--", "--dry-run"}, want: []string{"--", "abc123", "--dry-run"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeCommandArgs(definition, test.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("normalize = %v, want %v", got, test.want)
			}
		})
	}
}

func TestTerminalFormattingPolicy(t *testing.T) {
	tests := []struct {
		name      string
		globals   globalOptions
		environ   map[string]string
		stdinTTY  bool
		stdoutTTY bool
		color     bool
		interact  bool
		animate   bool
	}{
		{name: "terminal", stdinTTY: true, stdoutTTY: true, color: true, interact: true, animate: true},
		{name: "redirected", stdinTTY: true, stdoutTTY: false},
		{name: "no color flag", globals: globalOptions{noColor: true}, stdinTTY: true, stdoutTTY: true, interact: true},
		{name: "no color environment", environ: map[string]string{"NO_COLOR": ""}, stdinTTY: true, stdoutTTY: true, interact: true},
		{name: "dumb terminal", environ: map[string]string{"TERM": "dumb"}, stdinTTY: true, stdoutTTY: true, interact: true},
		{name: "no input", globals: globalOptions{noInput: true}, stdinTTY: true, stdoutTTY: true, color: true, animate: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			streams := cliIO{stdin: strings.NewReader(""), stdout: stdout, stderr: stderr, lookup: mapLookup(test.environ)}
			output := newTerminalOutputForTTY(streams, test.globals, test.stdinTTY, test.stdoutTTY)
			if output.color != test.color || output.interactive != test.interact || output.animation != test.animate {
				t.Fatalf("capabilities = color:%t interactive:%t animation:%t", output.color, output.interactive, output.animation)
			}
			styled := output.styled("31", "message")
			if !test.color && strings.Contains(styled, "\x1b[") {
				t.Fatalf("disabled color produced ANSI: %q", styled)
			}
			if err := output.progress("working"); err != nil {
				t.Fatal(err)
			}
			if !test.animate && strings.Contains(stderr.String(), "\r") {
				t.Fatalf("disabled animation rewrote a line: %q", stderr.String())
			}
		})
	}
}

func testCLI(environ map[string]string) (*bytes.Buffer, *bytes.Buffer, *cli) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command := newCLI(cliIO{
		stdin: strings.NewReader(""), stdout: stdout, stderr: stderr, lookup: mapLookup(environ),
	})
	return stdout, stderr, command
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("output does not match %s\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

// errorsAs keeps the test focused on the public exit-code contract.
func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}
