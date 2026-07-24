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
	{names: []string{"-c", "--config"}, valueName: "PATH", description: "use only this machine or project config"},
	{names: []string{"--no-input"}, description: "disable prompts; does not confirm changes"},
	{names: []string{"--no-color"}, description: "disable color and terminal formatting"},
	{names: []string{"-h", "--help"}, description: "show help and exit"},
	{names: []string{"--version"}, description: "show version and exit"},
}

// commandDefinitions is the single catalog used for routing, parsing, and help.
// The final command surface and help are defined here without compatibility aliases.
var commandDefinitions = []commandDefinition{
	{
		path: []string{"scan"}, usage: "vuelta scan [-p NAME | -d PATH | --all] [options] [config-path]",
		description: "find vulnerabilities and package candidates; create snapshots only for safely mutable manifests", group: "Everyday commands",
		examples: []string{"vuelta scan", "vuelta scan --project api", "vuelta scan --directory .", "vuelta scan --all --json"},
		options: []optionDefinition{
			{names: []string{"-p", "--project"}, valueName: "NAME", description: "scan one configured project"},
			{names: []string{"-d", "--directory"}, valueName: "PATH", description: "scan an explicit registered or adhoc directory"},
			{names: []string{"--all"}, description: "scan every configured project"},
			{names: []string{"--only"}, valueName: "MODE", description: "scan only vulnerabilities or packages"},
			{names: []string{"--policy"}, valueName: "PATH", description: "use an optional standalone package policy"},
			{names: []string{"--min-release-age"}, valueName: "DURATION", description: "minimum candidate age (default 7d; 0 disables)"},
			{names: []string{"--allow-project-config"}, description: "honor reviewed package-manager configuration"},
			{names: []string{"--fail-on"}, valueName: "KIND", description: "return 5 when vulnerabilities are found"},
			{names: []string{"--verbose"}, description: "show technical stages, inputs, warnings, and error details"},
			{names: []string{"--json"}, description: "write the versioned JSON envelope"},
		},
		security:    []string{"Scan never modifies manifests, lock files, or source. On first use it atomically onboards versioned .vuelta.yaml plus the exact /.vuelta/ root ignore rule. Private reports and snapshots stay under the selected project. A requirements.txt-only Python project is candidate-scan-only and never creates an update snapshot. Package-manager and vulnerability tools run only in containers."},
		takesConfig: true, handler: "scan",
	},
	{
		path: []string{"update"}, usage: "vuelta update [options]",
		description: "apply the newest validated snapshot from one exact project", group: "Everyday commands",
		examples: []string{"vuelta update", "vuelta update --directory /path/to/project", "vuelta update --directory /path/to/project --snapshot SNAPSHOT_ID --yes --json"},
		options: []optionDefinition{
			{names: []string{"-d", "--directory"}, valueName: "PATH", description: "select one exact project root (default: current directory)"},
			{names: []string{"--snapshot"}, valueName: "ID", description: "select one exact snapshot from that project"},
			{names: []string{"--dry-run"}, description: "run in a disposable copy without durable changes"},
			{names: []string{"--yes"}, description: "confirm the displayed plan"},
			{names: []string{"--json"}, description: "write the versioned JSON envelope"},
			{names: []string{"--allow-scripts"}, description: "allow package lifecycle scripts"},
			{names: []string{"--allow-unverified-release-age"}, description: "allow candidates whose release age was not verified"},
		},
		security:    []string{"The target root is selected before any snapshot is opened. Only that project's bounded .vuelta/snapshots directory is considered; every plan is validated before environment checks and durable updates require confirmation."},
		takesConfig: true, handler: "update",
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
			{names: []string{"--package-manager"}, valueName: "NAME", description: "select the detected manager or requirements scan profile"},
			{names: []string{"--toolchain-profile"}, valueName: "ID", description: "select an explicit operator override instead of the detected default"},
			{names: []string{"--platform"}, valueName: "PLATFORM", description: "select linux/amd64 or linux/arm64"},
			{names: []string{"--verification"}, valueName: "NAME", description: "select a declarative verification candidate (repeatable)"},
			{names: []string{"--scan-only"}, description: "disable updates until a ready verification profile is configured"},
			{names: []string{"--branch"}, valueName: "NAME", description: "set the protected branch"},
			{names: []string{"--remote"}, valueName: "NAME", description: "set the Git remote"},
			{names: []string{"--allow-path"}, valueName: "PATH", description: "allow a changed path (repeatable)"},
			{names: []string{"--docker-file"}, valueName: "PATH", description: "select a Dockerfile (repeatable)"},
			{names: []string{"--runtime-image"}, valueName: "DIGEST", description: "set an immutable runtime image (repeatable)"},
			{names: []string{"--yes"}, description: "confirm the displayed config diff"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security: []string{"The selected path is detected without inspecting parent directories or executing project code. Verification uses explicit bounded argv; writes require a reviewed diff."}, takesConfig: true, handler: "project add",
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
		description: "create an empty validated configuration without scanner image pins", examples: []string{"vuelta config init", "vuelta config init --replace --yes"},
		options: []optionDefinition{
			{names: []string{"--replace"}, description: "replace an existing config after review"},
			{names: []string{"--yes"}, description: "confirm the displayed replacement diff"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security: []string{"Replacement requires --replace and confirmation; --yes confirms only the displayed diff."}, takesConfig: true, handler: "config init",
	},
	{
		path: []string{"config", "migrate"}, usage: "vuelta config migrate [options] [config-path]",
		description: "upgrade a recognized legacy machine config without replacing its settings", examples: []string{"vuelta config migrate", "vuelta config migrate --yes"},
		options: []optionDefinition{
			{names: []string{"--yes"}, description: "confirm the reviewed schema migration"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security: []string{"Only recognized schema migrations are applied. Compatible settings, comments, key order, ownership, and protected mode are preserved; retired fields are named before confirmation and unsupported versions fail closed."}, takesConfig: true, handler: "config migrate",
	},
	{
		path: []string{"environment"}, usage: "vuelta environment <command>",
		description: "trust local Docker environments", group: "Configuration",
		examples: []string{"vuelta environment bootstrap --socket /var/run/docker.sock"},
	},
	{
		path: []string{"environment", "bootstrap"}, usage: "vuelta environment bootstrap [options] [config-path]",
		description: "probe and trust one explicit local Docker socket", examples: []string{"vuelta environment bootstrap --socket /var/run/docker.sock", "vuelta --no-input environment bootstrap --socket /var/run/docker.sock --yes --json"},
		options: []optionDefinition{
			{names: []string{"--socket"}, valueName: "PATH", description: "probe this explicit local Unix socket"},
			{names: []string{"--yes"}, description: "confirm the displayed socket and daemon identity"},
			{names: []string{"--json"}, description: "write the versioned JSON envelope"},
			{names: []string{"--non-interactive"}, description: "legacy alias for --no-input"},
		},
		security:    []string{"Ambient Docker context, config, TLS, proxy, and credential settings are ignored. Trust is persisted only after the exact socket and daemon identity are displayed and confirmed."},
		takesConfig: true, handler: "environment bootstrap",
	},
	{
		path: []string{"help"}, usage: "vuelta help [command] [--all]",
		description: "show top-level or command-specific help", group: "Help",
		examples: []string{"vuelta help scan", "vuelta help update", "vuelta help --all"},
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
	if globals.noInput && (definition.handler == "config init" || definition.handler == "config migrate" || definition.handler == "project add" || definition.handler == "environment bootstrap") {
		commandArgs = append([]string{"--non-interactive"}, commandArgs...)
	}
	if globals.config != "" && definition.takesConfig && definition.handler != "update" {
		if containsArgument(commandArgs, "--") {
			commandArgs = append(commandArgs, globals.config)
		} else {
			commandArgs = append(commandArgs, "--", globals.config)
		}
	}
	normalized, err := normalizeCommandArgs(definition, commandArgs)
	if err != nil {
		if definition.handler == "scan" && scanJSONRequested(commandArgs) {
			return scanTopLevelFailure(true, "invalid_invocation", err, "Run vuelta help scan for usage")
		}
		if definition.handler == "environment bootstrap" && containsArgument(commandArgs, "--json") {
			return environmentBootstrapFailure(true, "invalid_invocation", err)
		}
		return err
	}
	if globals.noInput && definition.handler == "update" {
		normalized = append([]string{"--non-interactive"}, normalized...)
	}
	if globals.noInput && definition.handler == "scan" {
		normalized = append([]string{"--internal-no-input"}, normalized...)
	}
	if globals.config != "" && definition.handler == "update" {
		normalized = append([]string{"--internal-config", globals.config}, normalized...)
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
	case "scan":
		return runScan(args)
	case "update":
		return executeUpdate(args)
	case "config validate":
		return runConfig(append([]string{"validate"}, args...))
	case "config init":
		return runConfigInit(args)
	case "config migrate":
		return runConfigMigrate(args)
	case "environment bootstrap":
		return runEnvironmentBootstrap(args)
	case "project list":
		return runProjectList(args)
	case "project add":
		return runProjectAdd(args)
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
	writer.println("  vuelta scan --all --json")
	writer.println("  vuelta project add . --name api")
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
