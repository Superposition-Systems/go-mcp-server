package deploy

import (
	"strings"
	"testing"
)

func TestGenerateTraefikLabels(t *testing.T) {
	labels, err := GenerateTraefikLabels(TraefikConfig{
		ServiceName: "my-mcp",
		Hostname:    "my-mcp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"traefik.enable=true",
		"my-mcp.loadbalancer.server.port=8080",
		"my-mcp-default.rule=Host(`my-mcp.example.com`)",
		"my-mcp-health.rule=",
		"my-mcp-transport.rule=",
		"my-mcp-oauth.rule=",
		"my-mcp-authorize.rule=",
		"my-mcp-api.rule=",
		"my-mcp-security.headers.stsSeconds=31536000",
		"qa-gate",
		"/mcp",
		"letsencrypt",
	} {
		if !strings.Contains(labels, want) {
			t.Errorf("labels missing %q", want)
		}
	}
}

func TestGenerateTraefikLabelsCustomValues(t *testing.T) {
	labels, err := GenerateTraefikLabels(TraefikConfig{
		ServiceName:        "custom",
		Hostname:           "custom.example.com",
		Port:               "9090",
		MCPPath:            "/rpc",
		QAGateMiddleware:   "my-gate",
		CertResolver:       "cloudflare",
		SecurityMiddleware: "custom-sec",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"server.port=9090",
		"/rpc",
		"my-gate",
		"cloudflare",
		"custom-sec",
		"custom.example.com",
	} {
		if !strings.Contains(labels, want) {
			t.Errorf("labels missing %q", want)
		}
	}
}

func TestGenerateDockerfile(t *testing.T) {
	df, err := GenerateDockerfile(DockerfileConfig{
		BinaryName: "my-server",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"golang:1.25-alpine",
		"CGO_ENABLED=0",
		"-o my-server",
		"distroless/static-debian12",
		"EXPOSE 8080",
		"nonroot:nonroot",
		"ENTRYPOINT [\"/my-server\"]",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("dockerfile missing %q", want)
		}
	}
}

func TestGenerateDockerfileCustom(t *testing.T) {
	df, err := GenerateDockerfile(DockerfileConfig{
		GoVersion:  "1.24",
		BinaryName: "custom-api",
		Port:       "3000",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(df, "golang:1.24-alpine") {
		t.Error("missing custom Go version")
	}
	if !strings.Contains(df, "EXPOSE 3000") {
		t.Error("missing custom port")
	}
}
