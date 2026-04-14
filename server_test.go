package mcpserver

import "testing"

func TestSelfOriginFromExternalURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Common production shape — the vps-mcp case that surfaced this bug.
		{"https://vps-mcp.qa.superposition.systems", "https://vps-mcp.qa.superposition.systems"},
		// Trailing slash must not leak into the origin; Origin headers
		// never include a trailing slash.
		{"https://vps-mcp.qa.superposition.systems/", "https://vps-mcp.qa.superposition.systems"},
		// Non-standard port is part of the origin — do not strip it.
		{"https://mcp.example.com:8443", "https://mcp.example.com:8443"},
		// Path + query must be discarded — Origin is scheme+host[:port] only.
		{"https://mcp.example.com/mcp?debug=1", "https://mcp.example.com"},
		// Localhost development loopback — matches the dev-mode
		// ExternalURL carve-out in ListenAndServe.
		{"http://localhost:8080", "http://localhost:8080"},
		// Empty input: "no self-origin to inject" signal.
		{"", ""},
		// Malformed URL: caller treats as "no self-origin."
		{"not a url", ""},
		{"://missing-scheme", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := selfOriginFromExternalURL(tc.in)
			if got != tc.want {
				t.Errorf("selfOriginFromExternalURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
