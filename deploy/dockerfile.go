package deploy

import (
	"bytes"
	"text/template"
)

// DockerfileConfig holds parameters for generating a Dockerfile.
type DockerfileConfig struct {
	// GoVersion is the Go version for the builder stage (e.g. "1.25").
	GoVersion string

	// BinaryName is the output binary name (e.g. "my-mcp-server").
	BinaryName string

	// Port is the exposed container port (default "8080").
	Port string
}

const dockerfileTemplate = `FROM golang:{{.GoVersion}}-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o {{.BinaryName}} .

FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/{{.BinaryName}} /{{.BinaryName}}

EXPOSE {{.Port}}

USER nonroot:nonroot

ENTRYPOINT ["/{{.BinaryName}}"]
`

// GenerateDockerfile renders a two-stage Dockerfile for a Go MCP server.
// Uses distroless for minimal attack surface (~12 MB final image).
func GenerateDockerfile(cfg DockerfileConfig) (string, error) {
	if cfg.GoVersion == "" {
		cfg.GoVersion = "1.25"
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	t, err := template.New("dockerfile").Parse(dockerfileTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}
