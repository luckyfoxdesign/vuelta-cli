// Command vuelta scans vulnerabilities and repairs verified findings.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/configinit"
)

const (
	exitOK          = 0
	exitFailure     = 1
	exitConfig      = 2
	exitInterrupted = 130
)

// version is set at build time with -ldflags when a release is produced.
var version = "dev"
var executableName = "vuelta"

type commandError struct {
	code int
	err  error
}

func (e commandError) Error() string { return e.err.Error() }
func (e commandError) Unwrap() error { return e.err }

func fail(code int, format string, args ...any) error {
	return commandError{code: code, err: fmt.Errorf(format, args...)}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == cleanupGuardianCommand {
		if err := runCleanupGuardian(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "vuelta cleanup guardian:", err)
			os.Exit(exitFailure)
		}
		return
	}
	if os.Args[0] != "" {
		executableName = os.Args[0]
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vuelta:", err)
		var command commandError
		if errors.As(err, &command) {
			os.Exit(command.code)
		}
		os.Exit(exitConfig)
	}
}

func run(args []string) error {
	return newCLI(cliIO{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, lookup: os.LookupEnv}).run(args)
}

func defaultConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config directory: %w", err)
	}
	return filepath.Join(dir, "vuelta", "config.yaml"), nil
}

func configPath(args []string) (string, error) {
	if len(args) > 1 {
		return "", fail(exitConfig, "expected at most one config path")
	}
	if len(args) == 1 {
		return args[0], nil
	}
	path, err := defaultConfigPath()
	if err != nil {
		return "", fail(exitConfig, "%v", err)
	}
	return path, nil
}

func runConfig(args []string) error {
	if len(args) < 1 {
		return fail(exitConfig, "usage: vuelta config validate [--json] [config-path] | vuelta config init [--replace] [--yes] [config-path] | vuelta config migrate [--yes] [config-path]")
	}
	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:])
	case "init":
		return runConfigInit(args[1:])
	case "migrate":
		return runConfigMigrate(args[1:])
	default:
		return fail(exitConfig, "usage: vuelta config validate [--json] [config-path] | vuelta config init [--replace] [--yes] [config-path] | vuelta config migrate [--yes] [config-path]")
	}
}

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func runConfigInit(args []string) error {
	fs := flag.NewFlagSet("config init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	replace := fs.Bool("replace", false, "replace an existing config")
	yes := fs.Bool("yes", false, "confirm the displayed replacement diff")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for confirmation")
	if err := fs.Parse(args); err != nil {
		return fail(exitConfig, "%v", err)
	}
	positional := fs.Args()
	if len(positional) > 1 {
		return fail(exitConfig, "usage: vuelta config init [--replace] [--yes] [config-path]")
	}
	path, err := configPath(positional)
	if err != nil {
		return err
	}
	plan, err := configinit.PlanConfigWrite(configinit.NewConfig(), path, *replace)
	if err != nil {
		return fail(exitConfig, "%v", err)
	}
	if plan.Exists && plan.Changed {
		fmt.Fprint(os.Stderr, plan.Diff(path))
		if !*yes {
			if *nonInteractive || !configinit.IsTerminal(os.Stdin) {
				return fail(exitConfig, "replacement requires confirmation; rerun with --replace --yes")
			}
			confirmed, confirmErr := promptConfirmation("Replace this config?")
			if confirmErr != nil {
				return fail(exitConfig, "%v", confirmErr)
			}
			if !confirmed {
				return fail(exitConfig, "config replacement cancelled")
			}
		}
	}
	if err := plan.Apply(path); err != nil {
		return fail(exitConfig, "%v", err)
	}
	if plan.Exists {
		fmt.Printf("replaced validated config: %s\n", path)
	} else {
		fmt.Printf("created empty validated config: %s\n", path)
	}
	fmt.Println("scanner toolchains: detected defaults are built locally on first scan; update.toolchain_profiles is optional")
	fmt.Printf("Next: %s\n", displayCommand("environment", "bootstrap", "--config", path))
	return nil
}

func displayCommand(args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellArgument(executableName))
	for _, argument := range args {
		parts = append(parts, shellArgument(argument))
	}
	return strings.Join(parts, " ")
}

func shellArgument(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return false
		}
		return !strings.ContainsRune("_@%+=:,./-", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func promptChoice(flag string, options []string) (string, error) {
	if len(options) > 0 {
		fmt.Fprintf(os.Stderr, "%s is required; detected options: %s\n", flag, strings.Join(options, ", "))
	}
	fmt.Fprintf(os.Stderr, "%s: ", flag)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", fmt.Errorf("read %s: %w", flag, err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", flag)
	}
	return value, nil
}

func promptConfirmation(message string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", message)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(value) == 0 {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func runScan(args []string) error {
	return executeScan(args)
}
