package main

import "testing"

func TestParseAllowHostsAndSubdomainMatching(t *testing.T) {
	allow, err := parseAllowHosts("registry.npmjs.org, pypi.org")
	if err != nil {
		t.Fatalf("parseAllowHosts: %v", err)
	}
	p := proxy{allow: allow}
	for _, host := range []string{"registry.npmjs.org", "cdn.registry.npmjs.org", "pypi.org"} {
		if !p.allowed(host) {
			t.Fatalf("expected %q to be allowed", host)
		}
	}
	for _, host := range []string{"registry.npmjs.org.example", "127.0.0.1", "example.com"} {
		if p.allowed(host) {
			t.Fatalf("expected %q to be denied", host)
		}
	}
}

func TestParseAllowHostsRejectsEmptyAndIPValues(t *testing.T) {
	for _, value := range []string{"", "127.0.0.1", "pypi.org,/etc/passwd"} {
		if _, err := parseAllowHosts(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	host, port, err := splitTarget("registry.npmjs.org:443", "443")
	if err != nil || host != "registry.npmjs.org" || port != "443" {
		t.Fatalf("splitTarget = %q, %q, %v", host, port, err)
	}
}
