package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/configinit"
	"gopkg.in/yaml.v3"
)

func TestConfigMigratePreservesSettingsAndRequiresConfirmation(t *testing.T) {
	path := legacyMachineConfig(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := runConfigMigrate([]string{"--non-interactive", path}); err == nil || !strings.Contains(err.Error(), "requires confirmation") {
		t.Fatalf("unconfirmed migration error = %v", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(before) {
		t.Fatal("unconfirmed migration changed the config")
	}

	if err := runConfigMigrate([]string{"--yes", path}); err != nil {
		t.Fatalf("confirmed migration: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load migrated config: %v", err)
	}
	if loaded.SchemaVersion != config.CurrentSchemaVersion || loaded.Update.MinReleaseAgeDays != 7 {
		t.Fatalf("migrated config = %#v", loaded)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "# preserved machine settings") {
		t.Fatal("migration discarded an existing comment")
	}
}

func TestLoadMachineConfigOffersRecognizedMigrationAndCanCancel(t *testing.T) {
	previousPrompt := confirmSchemaMigration
	t.Cleanup(func() { confirmSchemaMigration = previousPrompt })

	t.Run("confirmed", func(t *testing.T) {
		path := legacyMachineConfig(t)
		confirmSchemaMigration = func() (bool, error) { return true, nil }
		loaded, err := loadMachineConfig(path, true)
		if err != nil {
			t.Fatalf("loadMachineConfig: %v", err)
		}
		if loaded.SchemaVersion != config.CurrentSchemaVersion {
			t.Fatalf("schema version = %d", loaded.SchemaVersion)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		path := legacyMachineConfig(t)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		confirmSchemaMigration = func() (bool, error) { return false, nil }
		if _, err := loadMachineConfig(path, true); err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Fatalf("cancelled migration error = %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Fatal("cancelled automatic migration changed the config")
		}
	})
}

func legacyMachineConfig(t *testing.T) string {
	t.Helper()
	data, err := yaml.Marshal(configinit.NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(data), "schema_version: 1\n", "", 1)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("# preserved machine settings\n"+legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
