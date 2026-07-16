package gitpath

import "testing"

func TestAllowedUsesFullRepositoryRelativePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{name: "root filename", path: "package.json", patterns: []string{"package.json"}, want: true},
		{name: "root filename rejects nested basename", path: "nested/package.json", patterns: []string{"package.json"}},
		{name: "explicit nested filename", path: "nested/package.json", patterns: []string{"nested/package.json"}, want: true},
		{name: "segment glob", path: "nested/package.json", patterns: []string{"nested/*.json"}, want: true},
		{name: "segment glob does not cross slash", path: "nested/deeper/package.json", patterns: []string{"nested/*.json"}},
		{name: "root glob stays at root", path: "nested/package.json", patterns: []string{"*.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Allowed(tt.path, tt.patterns)
			if err != nil {
				t.Fatalf("Allowed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Allowed(%q, %q) = %v, want %v", tt.path, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestValidatePatternRejectsAmbiguousPaths(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"", "/package.json", "../package.json", "nested/../package.json",
		"./package.json", "nested//package.json", `nested\package.json`,
		"C:/package.json", "**/package.json", "nested/[package.json",
		"package.json/",
	}
	for _, pattern := range invalid {
		pattern := pattern
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			if err := ValidatePattern(pattern); err == nil {
				t.Fatalf("ValidatePattern(%q) succeeded, want error", pattern)
			}
		})
	}
}
