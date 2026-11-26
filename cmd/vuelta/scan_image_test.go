package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltImageCLIHelpAndRouting(t *testing.T) {
	stdout, _, command := testCLI(nil)
	if err := command.run([]string{"scan", "image", "--help"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--allow-repository", "metadata.json", "--timeout"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %s", want)
		}
	}
	definition, args, err := resolveCommand([]string{"scan", "image", "--allow-repository", "ghcr.io/example/app"})
	if err != nil || definition.handler != "scan image" || len(args) != 2 {
		t.Fatalf("%+v %v %v", definition, args, err)
	}
}

func TestBuiltImageCLIFailsBeforeDockerWithVersionedJSON(t *testing.T) {
	valid := `{"schema_version":1,"artifact":{"project":"api","sha":"` + strings.Repeat("b", 40) + `","image":"ghcr.io/example/app@sha256:` + strings.Repeat("a", 64) + `","platform":"linux/amd64"}}`
	for _, test := range []struct {
		name, input, code string
		args              []string
	}{
		{"mutable tag", strings.ReplaceAll(valid, "@sha256:"+strings.Repeat("a", 64), ":latest"), "invalid_image_input", nil},
		{"valid input needs machine trust", valid, "configuration_unavailable", nil},
		{"unknown option", valid, "invalid_invocation", []string{"--socket", "/untrusted.sock"}},
		{"excessive timeout", valid, "invalid_invocation", []string{"--timeout", "2h"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.WriteString(test.input); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			previous := os.Stdin
			os.Stdin = reader
			defer func() { os.Stdin = previous; _ = reader.Close() }()
			args := append([]string{"scan", "image", "--allow-repository", "ghcr.io/example/app"}, test.args...)
			args = append(args, "--config", filepath.Join(t.TempDir(), "missing.yaml"))
			var commandErr error
			stdout, _ := captureScanOutput(t, func() { commandErr = run(args) })
			var coded commandError
			if !errors.As(commandErr, &coded) || coded.code != exitConfig {
				t.Fatalf("%v", commandErr)
			}
			var report struct {
				SchemaVersion int `json:"schema_version"`
				Status, Error string
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil || report.SchemaVersion != 1 || report.Status != "failed" || report.Error != test.code {
				t.Fatalf("%s %v", stdout, err)
			}
		})
	}
}
