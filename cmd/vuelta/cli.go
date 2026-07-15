package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type optionDefinition struct {
	names       []string
	valueName   string
	description string
}

func (o optionDefinition) takesValue() bool { return o.valueName != "" }

type commandDefinition struct {
	path        []string
	usage       string
	description string
	group       string
	examples    []string
	options     []optionDefinition
	security    []string
	hidden      bool
	takesConfig bool
	handler     string
}

var globalOptionDefinitions = []optionDefinition{
	{names: []string{"-c", "--config"}, valueName: "PATH", description: "use an alternate config.yaml"},
	{names: []string{"--no-input"}, description: "disable prompts; does not confirm changes"},
	{names: []string{"--no-color"}, description: "disable color and terminal formatting"},
	{names: []string{"-h", "--help"}, description: "show help and exit"},
	{names: []string{"--version"}, description: "show version and exit"},
}

// commandDefinitions is the single catalog used for routing, parsing, and help.
// Later CLI redesign phases can add commands without duplicating usage strings.
var commandDefinitions = []commandDefinition{
	{
		path: []string{"run"}, usage: "vuelta run [options] [config-path]",
		description: "run the configured update pipeline", group: "Everyday commands",
		examples: []string{"vuelta run --dry-run", "vuelta run --project api"},
		options: []optionDefinition{
			{names: []string{"--dry-run"}, description: "run without commit, push, or deploy candidate"},
			{names: []string{"--project"}, valueName: "NAME", description: "run one configured project"},
			{names: []string{"--lock"}, valueName: "PATH", description: "use an alternate process lock"},
			{names: []string{"--json-logs"}, description: "write JSON log records"},
		},
		security: []string{"Dry-run still performs configured security and environment checks."}, takesConfig: true, handler: "run",
	},
	{
		path: []string{"scan"}, usage: "vuelta scan [options] [config-path]",
		description: "scan configured projects for security findings", group: "Everyday commands",
		examples:    []string{"vuelta scan", "vuelta scan --project api"},
		options:     []optionDefinition{{names: []string{"--project"}, valueName: "NAME", description: "scan one configured project"}},
		takesConfig: true, handler: "scan",
	},
	{
		path: []string{"package"}, usage: "vuelta package <command>",
		description: "inspect or apply dependency updates", group: "Everyday commands",
		examples: []string{"vuelta package scan", "vuelta package update --snapshot SNAPSHOT_ID"},
	},
	{
		path: []string{"package", "scan"}, usage: "vuelta package scan [options] [config-path]",
		description: "create package-update snapshots", examples: []string{"vuelta package scan", "vuelta package scan --project api --json"},
		options: []optionDefinition{
			{names: []string{"--project"}, valueName: "NAME", description: "scan one configured project"},
			{names: []string{"--json"}, description: "write machine-readable snapshots"},
		},
		takesConfig: true, handler: "package scan",
	},
	{
		path: []string{"package", "update"}, usage: "vuelta package update --snapshot ID [options] [config-path]",
		description: "apply a validated package snapshot", examples: []string{"vuelta package update --snapshot abc123", "vuelta package update --snapshot abc123 --dry-run"},
		options: []optionDefinition{
			{names: []string{"--snapshot"}, valueName: "ID", description: "snapshot returned by package scan (required)"},
			{names: []string{"--dry-run"}, description: "run checks and tests without commit or push"},
		},
		security: []string{"A snapshot is revalidated before any update runs."}, takesConfig: true, handler: "package update",
	},
	{
		path: []string{"package", "local"}, usage: "vuelta package local <command>",
		description: "inspect or update a project with explicitly local tools", examples: []string{"vuelta package local scan .", "vuelta package local update --policy local.yaml --package example@1.2.3 --dry-run ."},
		security: []string{"Local mode is less isolated and never implies permission to write."},
	},
	{
		path: []string{"package", "local", "scan"}, usage: "vuelta package local scan [options] <project-path>",
		description: "scan one project with local package-manager tools", examples: []string{"vuelta package local scan .", "vuelta package local scan . --policy local.yaml --json"},
		options: []optionDefinition{
			{names: []string{"--policy"}, valueName: "PATH", description: "use a standalone local package policy"},
			{names: []string{"--json"}, description: "write machine-readable candidates"},
			{names: []string{"--allow-project-config"}, description: "honor reviewed project package-manager configuration"},
		},
		security: []string{"Local scan does not provide Docker isolation or run CVE scanners."}, handler: "package local scan",
	},
	{
		path: []string{"package", "local", "update"}, usage: "vuelta package local update --policy PATH --package NAME@VERSION [options] <project-path>",
		description: "apply selected updates with local package-manager tools", examples: []string{"vuelta package local update --policy local.yaml --package example@1.2.3 --dry-run ."},
		options: []optionDefinition{
			{names: []string{"--policy"}, valueName: "PATH", description: "use a standalone local package policy (required)"},
			{names: []string{"--package"}, valueName: "NAME@VERSION", description: "select an update (repeatable)"},
			{names: []string{"--apply"}, description: "explicitly permit manifest and lock-file writes"},
			{names: []string{"--dry-run"}, description: "validate without writing"},
			{names: []string{"--allow-project-config"}, description: "honor reviewed project package-manager configuration"},
			{names: []string{"--allow-scripts"}, description: "allow package lifecycle scripts on the host"},
		},
		security: []string{"--apply permits writes; --allow-scripts permits third-party code to run on the host."}, handler: "package local update",
	},
	{
		path: []string{"project"}, usage: "vuelta project <command>",
		description: "list or add configured projects", group: "Configuration",
		examples: []string{"vuelta project list", "vuelta project add . --name api"},
	},
	{
		path: []string{"project", "list"}, usage: "vuelta project list [--json] [config-path]",
		description: "list stable project names and canonical paths", examples: []string{"vuelta project list", "vuelta project list --json"},
		options:     []optionDefinition{{names: []string{"--json"}, description: "write the versioned JSON envelope"}},
		takesConfig: true, handler: "project list",
	},
	{
		path: []string{"project", "add"}, usage: "vuelta project add [options] <path> [config-path]",
		description: "detect and add one project", examples: []string{"vuelta project add . --name api", "vuelta project add . --name api --no-input --branch main --remote origin --yes"},
		options: []optionDefinition{
			{names: []string{"--name"}, valueName: "NAME", description: "set the persistent project name (defaults to path basename)"},
			{names: []string{"--stack"}, valueName: "STACK", description: "select python, node, or docker"},
			{names: []string{"--package-manager"}, valueName: "NAME", description: "select the Python or Node package manager"},
			{names: []string{"--compose-file"}, valueName: "PATH", description: "set the project-relative Compose file"},
			{names: []string{"--test-service"}, valueName: "NAME", description: "set the Compose test service"},
			{names: []string{"--branch"}, valueName: "NAME", description: "set the protected branch"},
			{names: []string{"--remote"}, valueName: "NAME", description: "set the Git remote"},
			{names: []string{"--allow-path"}, valueName: "PATH", description: "allow a changed path (repeatable)"},
			{names: []string{"--docker-file"}, valueName: "PATH", description: "select a Dockerfile (repeatable)"},
			{names: []string{"--runtime-image"}, valueName: "DIGEST", description: "set an immutable runtime image (repeatable)"},
			{names: []string{"--yes"}, description: "confirm the displayed config diff"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security: []string{"The selected path is detected without inspecting parent directories; writes require a reviewed diff."}, takesConfig: true, handler: "project add",
	},
	{
		path: []string{"config"}, usage: "vuelta config <command>",
		description: "create or validate configuration", group: "Configuration",
		examples: []string{"vuelta config init", "vuelta config validate"},
	},
	{
		path: []string{"config", "validate"}, usage: "vuelta config validate [--json] [config-path]",
		description: "validate the selected configuration", examples: []string{"vuelta config validate", "vuelta --config ./vuelta.yaml config validate --json"},
		options:     []optionDefinition{{names: []string{"--json"}, description: "write the versioned JSON envelope"}},
		takesConfig: true, handler: "config validate",
	},
	{
		path: []string{"config", "init"}, usage: "vuelta config init [options] [config-path]",
		description: "create an empty validated configuration", examples: []string{"vuelta config init", "vuelta config init --replace --yes"},
		options: []optionDefinition{
			{names: []string{"--replace"}, description: "replace an existing config after review"},
			{names: []string{"--yes"}, description: "confirm the displayed replacement diff"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security: []string{"Replacement requires --replace and confirmation; --yes confirms only the displayed diff."}, takesConfig: true, handler: "config init",
	},
	{
		path: []string{"tasks"}, usage: "vuelta tasks <command>",
		description: "inspect deployment tasks", group: "Operations",
		examples: []string{"vuelta tasks list"},
	},
	{
		path: []string{"tasks", "list"}, usage: "vuelta tasks list [config-path]",
		description: "list pending deployment candidates", examples: []string{"vuelta tasks list"},
		takesConfig: true, handler: "tasks list",
	},
	{
		path: []string{"deploy"}, usage: "vuelta deploy <command>",
		description: "enqueue or process deployment candidates", group: "CI and server commands", hidden: true,
		examples: []string{"vuelta deploy enqueue --project api --commit SHA --image-digest SHA256 --manifest-digest SHA256", "vuelta deploy worker"},
	},
	{
		path: []string{"deploy", "enqueue"}, usage: "vuelta deploy enqueue --project NAME --commit SHA --image-digest SHA256 --manifest-digest SHA256 [config-path]",
		description: "enqueue an approved immutable deployment candidate", hidden: true,
		options: []optionDefinition{
			{names: []string{"--project"}, valueName: "NAME", description: "configured project name (required)"},
			{names: []string{"--commit"}, valueName: "SHA", description: "approved full commit SHA (required)"},
			{names: []string{"--image-digest"}, valueName: "SHA256", description: "verified OCI image digest (required)"},
			{names: []string{"--manifest-digest"}, valueName: "SHA256", description: "verified deploy manifest digest (required)"},
		},
		takesConfig: true, handler: "deploy enqueue",
	},
	{
		path: []string{"deploy", "worker"}, usage: "vuelta deploy worker [config-path]",
		description: "process authenticated deployment candidates", hidden: true,
		takesConfig: true, handler: "deploy worker",
	},
	{
		path: []string{"help"}, usage: "vuelta help [command] [--all]",
		description: "show top-level or command-specific help", group: "Help",
		examples: []string{"vuelta help scan", "vuelta help package update", "vuelta help --all"},
		options:  []optionDefinition{{names: []string{"--all"}, description: "include CI and server commands"}}, handler: "help",
	},
}

type globalOptions struct {
	config  string
	noInput bool
	noColor bool
	help    bool
	version bool
}

type cliIO struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	lookup func(string) (string, bool)
}

type cli struct {
	io  cliIO
	out terminalOutput
}

func newCLI(streams cliIO) *cli {
	if streams.stdin == nil {
		streams.stdin = strings.NewReader("")
	}
	if streams.stdout == nil {
		streams.stdout = io.Discard
	}
	if streams.stderr == nil {
		streams.stderr = io.Discard
	}
	if streams.lookup == nil {
		streams.lookup = os.LookupEnv
	}
	return &cli{io: streams}
}

func (c *cli) run(args []string) error {
	globals, remaining, err := parseGlobalOptions(args)
	if err != nil {
		return err
	}
	c.out = newTerminalOutput(c.io, globals)
	if globals.version {
		writer := newTextWriter(c.out.stdout)
		writer.printf("vuelta %s\n", version)
		return writer.result()
	}
	if len(remaining) == 0 {
		return c.writeTopLevelHelp(false)
	}
	definition, commandArgs, err := resolveCommand(remaining)
	if err != nil {
		return err
	}
	if definition.handler == "help" {
		return c.runHelp(commandArgs)
	}
	if globals.help {
		return c.writeCommandHelp(definition)
	}
	if definition.handler == "" {
		return c.writeCommandHelp(definition)
	}
	if globals.noInput && (definition.handler == "config init" || definition.handler == "project add") {
		commandArgs = append([]string{"--non-interactive"}, commandArgs...)
	}
	if globals.config != "" && definition.takesConfig {
		if containsArgument(commandArgs, "--") {
			commandArgs = append(commandArgs, globals.config)
		} else {
			commandArgs = append(commandArgs, "--", globals.config)
		}
	}
	normalized, err := normalizeCommandArgs(definition, commandArgs)
	if err != nil {
		return err
	}
	return dispatchCommand(definition.handler, normalized)
}

func containsArgument(args []string, wanted string) bool {
	for _, argument := range args {
		if argument == wanted {
			return true
		}
	}
	return false
}

func parseGlobalOptions(args []string) (globalOptions, []string, error) {
	var options globalOptions
	remaining := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			remaining = append(remaining, args[index:]...)
			break
		}
		name, value, hasValue := strings.Cut(argument, "=")
		switch name {
		case "-c", "--config":
			if !hasValue {
				index++
				if index >= len(args) {
					return globalOptions{}, nil, fail(exitConfig, "%s requires PATH", name)
				}
				value = args[index]
			}
			if value == "" {
				return globalOptions{}, nil, fail(exitConfig, "%s requires PATH", name)
			}
			if options.config != "" {
				return globalOptions{}, nil, fail(exitConfig, "--config may be specified only once")
			}
			options.config = value
		case "--no-input":
			if hasValue {
				return globalOptions{}, nil, fail(exitConfig, "--no-input does not take a value")
			}
			options.noInput = true
		case "--no-color":
			if hasValue {
				return globalOptions{}, nil, fail(exitConfig, "--no-color does not take a value")
			}
			options.noColor = true
		case "-h", "--help":
			if hasValue {
				return globalOptions{}, nil, fail(exitConfig, "%s does not take a value", name)
			}
			options.help = true
		case "--version":
			if hasValue {
				return globalOptions{}, nil, fail(exitConfig, "--version does not take a value")
			}
			options.version = true
		default:
			remaining = append(remaining, argument)
		}
	}
	return options, remaining, nil
}

func resolveCommand(args []string) (commandDefinition, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return commandDefinition{}, nil, fail(exitConfig, "expected a command; run 'vuelta help'")
	}
	path := make([]string, 0, 3)
	index := 0
	var current commandDefinition
	for index < len(args) {
		children := childCommands(path)
		if len(children) == 0 {
			break
		}
		argument := args[index]
		if strings.HasPrefix(argument, "-") || argument == "--" {
			break
		}
		match, ok := findChild(children, argument)
		if !ok {
			prefix := ""
			if len(path) > 0 {
				prefix = strings.Join(path, " ") + " "
			}
			message := fmt.Sprintf("unknown command %q", prefix+argument)
			if suggestion := nearestName(argument, childNames(children)); suggestion != "" {
				message += fmt.Sprintf("\nDid you mean %q?", prefix+suggestion)
			}
			helpCommand := "vuelta help"
			if len(path) > 0 {
				helpCommand += " " + strings.Join(path, " ")
			}
			return commandDefinition{}, nil, fail(exitConfig, "%s\nRun '%s' for available commands.", message, helpCommand)
		}
		current = match
		path = append(path, argument)
		index++
		if current.handler != "" {
			break
		}
	}
	if len(path) == 0 {
		return commandDefinition{}, nil, fail(exitConfig, "expected a command; run 'vuelta help'")
	}
	return current, args[index:], nil
}

func childCommands(parent []string) []commandDefinition {
	children := make([]commandDefinition, 0)
	for _, definition := range commandDefinitions {
		if len(definition.path) != len(parent)+1 {
			continue
		}
		matches := true
		for index := range parent {
			if definition.path[index] != parent[index] {
				matches = false
				break
			}
		}
		if matches {
			children = append(children, definition)
		}
	}
	return children
}

func findChild(children []commandDefinition, name string) (commandDefinition, bool) {
	for _, child := range children {
		if child.path[len(child.path)-1] == name {
			return child, true
		}
	}
	return commandDefinition{}, false
}

func childNames(children []commandDefinition) []string {
	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, child.path[len(child.path)-1])
	}
	return names
}

func normalizeCommandArgs(definition commandDefinition, args []string) ([]string, error) {
	options := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	terminated := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if terminated {
			positionals = append(positionals, argument)
			continue
		}
		if argument == "--" {
			terminated = true
			continue
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, argument)
			continue
		}
		name, value, hasValue := strings.Cut(argument, "=")
		option, ok := findOption(definition.options, name)
		if !ok {
			message := fmt.Sprintf("unknown option %q for %s", name, strings.Join(definition.path, " "))
			if suggestion := nearestName(name, optionNames(definition.options)); suggestion != "" {
				message += fmt.Sprintf("\nDid you mean %q?", suggestion)
			}
			return nil, fail(exitConfig, "%s\nRun 'vuelta help %s' for usage.", message, strings.Join(definition.path, " "))
		}
		if option.takesValue() {
			if hasValue {
				if value == "" {
					return nil, fail(exitConfig, "%s requires %s", name, option.valueName)
				}
				options = append(options, argument)
				continue
			}
			index++
			if index >= len(args) || args[index] == "--" {
				return nil, fail(exitConfig, "%s requires %s", name, option.valueName)
			}
			options = append(options, argument, args[index])
			continue
		}
		if hasValue && value == "" {
			return nil, fail(exitConfig, "%s requires a boolean value after '='", name)
		}
		options = append(options, argument)
	}
	if terminated {
		options = append(options, "--")
	}
	return append(options, positionals...), nil
}

func findOption(options []optionDefinition, name string) (optionDefinition, bool) {
	for _, option := range options {
		for _, candidate := range option.names {
			if candidate == name {
				return option, true
			}
		}
	}
	return optionDefinition{}, false
}

func optionNames(options []optionDefinition) []string {
	names := make([]string, 0, len(options))
	for _, option := range options {
		names = append(names, option.names...)
	}
	return names
}

func dispatchCommand(handler string, args []string) error {
	switch handler {
	case "run":
		return runPipeline(args)
	case "scan":
		return runScan(args)
	case "package scan":
		return runPackage(append([]string{"scan"}, args...))
	case "package update":
		return runPackage(append([]string{"update"}, args...))
	case "package local scan":
		return runPackage(append([]string{"local", "scan"}, args...))
	case "package local update":
		return runPackage(append([]string{"local", "update"}, args...))
	case "config validate":
		return runConfig(append([]string{"validate"}, args...))
	case "config init":
		return runConfigInit(args)
	case "project list":
		return runProjectList(args)
	case "project add":
		return runProjectAdd(args)
	case "tasks list":
		return runTasks(append([]string{"list"}, args...))
	case "deploy enqueue":
		return runDeploy(append([]string{"enqueue"}, args...))
	case "deploy worker":
		return runDeployWorker(args)
	default:
		return fail(exitConfig, "command %q is not executable", handler)
	}
}

func (c *cli) runHelp(args []string) error {
	showAll := false
	path := make([]string, 0, len(args))
	for _, argument := range args {
		switch argument {
		case "--all":
			showAll = true
		case "--":
			continue
		default:
			if strings.HasPrefix(argument, "-") {
				return fail(exitConfig, "unknown option %q for help", argument)
			}
			path = append(path, argument)
		}
	}
	if len(path) == 0 {
		return c.writeTopLevelHelp(showAll)
	}
	definition, rest, err := resolveCommand(path)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fail(exitConfig, "unexpected help topic %q", strings.Join(rest, " "))
	}
	return c.writeCommandHelp(definition)
}

func (c *cli) writeTopLevelHelp(showAll bool) error {
	writer := newTextWriter(c.out.stdout)
	writer.println("vuelta — checks and safely updates dependencies")
	writer.println()
	writer.println("Examples:")
	writer.println("  vuelta scan")
	writer.println("  vuelta package scan --project api")
	writer.println("  vuelta run --dry-run")
	writer.println()
	groups := []string{"Everyday commands", "Configuration", "Operations", "Help", "CI and server commands"}
	for _, group := range groups {
		if group == "CI and server commands" && !showAll {
			continue
		}
		entries := make([]commandDefinition, 0)
		for _, definition := range commandDefinitions {
			if len(definition.path) == 1 && definition.group == group && (!definition.hidden || showAll) {
				entries = append(entries, definition)
			}
		}
		if len(entries) == 0 {
			continue
		}
		writer.printf("%s:\n", group)
		for _, definition := range entries {
			writer.printf("  %-12s %s\n", definition.path[0], definition.description)
		}
		writer.println()
	}
	writer.println("Global options:")
	writeOptions(writer, globalOptionDefinitions)
	writer.println()
	writer.println("Run 'vuelta help <command>' for command details.")
	if !showAll {
		writer.println("Run 'vuelta help --all' to include CI and server commands.")
	}
	return writer.result()
}

func (c *cli) writeCommandHelp(definition commandDefinition) error {
	writer := newTextWriter(c.out.stdout)
	name := strings.Join(definition.path, " ")
	writer.printf("vuelta %s — %s\n\n", name, definition.description)
	if len(definition.examples) > 0 {
		writer.println("Examples:")
		for _, example := range definition.examples {
			writer.printf("  %s\n", example)
		}
		writer.println()
	}
	writer.println("Usage:")
	writer.printf("  %s\n", definition.usage)
	children := childCommands(definition.path)
	if len(children) > 0 {
		writer.println()
		writer.println("Commands:")
		for _, child := range children {
			writer.printf("  %-12s %s\n", child.path[len(child.path)-1], child.description)
		}
	}
	if len(definition.options) > 0 {
		writer.println()
		writer.println("Options:")
		writeOptions(writer, definition.options)
	}
	defaults := commandDefaults(definition)
	if len(defaults) > 0 {
		writer.println()
		writer.println("Defaults:")
		for _, note := range defaults {
			writer.printf("  %s\n", note)
		}
	}
	writer.println()
	writer.println("Global options:")
	writeOptions(writer, globalOptionDefinitions)
	if len(definition.security) > 0 {
		writer.println()
		writer.println("Security:")
		for _, note := range definition.security {
			writer.printf("  %s\n", note)
		}
	}
	return writer.result()
}

func commandDefaults(definition commandDefinition) []string {
	defaults := make([]string, 0, 2)
	if definition.takesConfig {
		defaults = append(defaults, "Config: operating system user config path unless --config or config-path is set.")
	}
	for _, option := range definition.options {
		if !option.takesValue() {
			defaults = append(defaults, "Boolean options: disabled unless specified.")
			break
		}
	}
	return defaults
}

func writeOptions(writer *textWriter, options []optionDefinition) {
	for _, option := range options {
		label := strings.Join(option.names, ", ")
		if option.valueName != "" {
			label += " " + option.valueName
		}
		writer.printf("  %-26s %s\n", label, option.description)
	}
}

type textWriter struct {
	destination io.Writer
	err         error
}

func newTextWriter(destination io.Writer) *textWriter {
	return &textWriter{destination: destination}
}

func (w *textWriter) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintf(w.destination, format, args...)
}

func (w *textWriter) println(args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintln(w.destination, args...)
}

func (w *textWriter) result() error {
	if w.err != nil {
		return fail(exitFailure, "write output: %v", w.err)
	}
	return nil
}

func nearestName(value string, candidates []string) string {
	sort.Strings(candidates)
	best := ""
	bestDistance := len(value) + 1
	for _, candidate := range candidates {
		distance := editDistance(value, candidate)
		if distance < bestDistance {
			best = candidate
			bestDistance = distance
		}
	}
	limit := 2
	if len(value) > 8 {
		limit = 3
	}
	if bestDistance > limit {
		return ""
	}
	return best
}

func editDistance(left, right string) int {
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex, leftRune := range left {
		current := make([]int, len(right)+1)
		current[0] = leftIndex + 1
		for rightIndex, rightRune := range right {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			current[rightIndex+1] = min(current[rightIndex]+1, previous[rightIndex+1]+1, previous[rightIndex]+cost)
		}
		previous = current
	}
	return previous[len(right)]
}

type terminalOutput struct {
	stdout      io.Writer
	stderr      io.Writer
	color       bool
	interactive bool
	animation   bool
}

func newTerminalOutput(streams cliIO, globals globalOptions) terminalOutput {
	return newTerminalOutputForTTY(streams, globals, isTerminal(streams.stdin), isTerminal(streams.stdout))
}

func newTerminalOutputForTTY(streams cliIO, globals globalOptions, stdinTTY, stdoutTTY bool) terminalOutput {
	_, noColorEnvironment := streams.lookup("NO_COLOR")
	term, _ := streams.lookup("TERM")
	return terminalOutput{
		stdout: streams.stdout, stderr: streams.stderr,
		color:       stdoutTTY && !globals.noColor && !noColorEnvironment && term != "dumb",
		interactive: stdinTTY && stdoutTTY && !globals.noInput,
		animation:   stdoutTTY && !globals.noColor && !noColorEnvironment && term != "dumb",
	}
}

func isTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (o terminalOutput) styled(code, text string) string {
	if !o.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (o terminalOutput) progress(message string) error {
	writer := newTextWriter(o.stderr)
	if o.animation {
		writer.printf("\r%s", message)
		return writer.result()
	}
	writer.println(message)
	return writer.result()
}
