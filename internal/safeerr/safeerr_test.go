package safeerr

import "testing"

func TestRedactMasksCredentialLikeSubstrings(t *testing.T) {
	cases := []struct{ name, text, mustNotContain string }{
		{"token assignment", "request failed: token=abc123secret", "abc123secret"},
		{"bearer header", "Authorization: Bearer abc.def.ghi", "abc.def.ghi"},
		{"userinfo url", "dial tcp https://user:hunter2@registry.internal/v2", "hunter2"},
		{"password field", `config error: password="s3cr3t!"`, "s3cr3t!"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.text)
			if got == c.text {
				t.Fatalf("Redact(%q) did not change input", c.text)
			}
			if contains(got, c.mustNotContain) {
				t.Fatalf("Redact(%q) = %q, still contains secret", c.text, got)
			}
		})
	}
}

func TestRedactLeavesBenignTextUnchanged(t *testing.T) {
	text := "permission denied: cannot write /var/lib/docker"
	if got := Redact(text); got != text {
		t.Fatalf("Redact(%q) = %q, want unchanged", text, got)
	}
}

func TestTailBoundsAndRedacts(t *testing.T) {
	data := []byte("line one\nline two: token=abc123secret\nline three")
	got := Tail(data, 16)
	if len(got) > 16 {
		t.Fatalf("Tail exceeded bound: %d bytes", len(got))
	}
	full := Tail(data, 4096)
	if contains(full, "abc123secret") {
		t.Fatalf("Tail did not redact: %q", full)
	}
}

func TestClassifyDetailHeuristics(t *testing.T) {
	cases := []struct {
		detail string
		want   Category
	}{
		{"", CategoryUnknown},
		{"permission denied while writing", CategoryPermission},
		{"operation not permitted", CategoryPermission},
		{"no matching manifest for linux/arm64", CategoryImagePlatform},
		{"proxy.url must be a non-empty string", CategoryEgress},
		{"dial tcp: lookup registry.invalid: no such host", CategoryEndpoint},
		{"connection refused", CategoryEndpoint},
		{"unknown flag: --cooldown", CategoryUnsupportedFlag},
		{"something entirely unrecognized happened", CategoryUnsupportedFlag},
		{"an unrelated failure with no known shape", CategoryUnknown},
	}
	for _, c := range cases {
		if got := ClassifyDetail(c.detail); got != c.want {
			t.Errorf("ClassifyDetail(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
