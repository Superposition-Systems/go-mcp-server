// Package deploy provides generators for deployment configuration files.
//
// The Traefik label generator produces docker-compose labels that implement
// the correct routing split for MCP servers:
//   - /health, /healthz: public (rate-limited)
//   - /mcp: public (app handles Bearer/OAuth auth)
//   - /.well-known/*, /token, /register: public (OAuth server-to-server)
//   - /authorize: behind qa-gate (human PIN entry)
//   - /api/*: behind qa-gate (browser access)
//   - catch-all: behind qa-gate
//
// Priority ordering ensures specific routes match before the catch-all.
package deploy

import (
	"bytes"
	"text/template"
)

// TraefikConfig holds the parameters for generating Traefik docker-compose labels.
type TraefikConfig struct {
	// ServiceName is the docker-compose service name and Traefik service ID
	// (e.g. "claude-logs-api", "voxhub-mcp").
	ServiceName string

	// Hostname is the FQDN for routing (e.g. "my-mcp.qa.superposition.systems").
	Hostname string

	// Port is the container port (default "8080").
	Port string

	// MCPPath is the MCP endpoint path (default "/mcp").
	MCPPath string

	// SecurityMiddleware is the name for the security headers middleware
	// (e.g. "my-mcp-security"). If empty, defaults to ServiceName + "-security".
	SecurityMiddleware string

	// QAGateMiddleware is the name of the shared forward-auth middleware
	// (default "qa-gate").
	QAGateMiddleware string

	// CertResolver is the Traefik cert resolver name (default "letsencrypt").
	CertResolver string
}

const traefikTemplate = `    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=web"

      # Service definition
      - "traefik.http.services.{{.ServiceName}}.loadbalancer.server.port={{.Port}}"

      # -----------------------------------------------------------------------
      # Default router (behind {{.QAGateMiddleware}} — catch-all for browser access)
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-default.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `)"
      - "traefik.http.routers.{{.ServiceName}}-default.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-default.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-default.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-default.middlewares=rate-limit,{{.QAGateMiddleware}},{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # Health check (public)
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-health.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `) && (Path(` + "`" + `/health` + "`" + `) || Path(` + "`" + `/healthz` + "`" + `))"
      - "traefik.http.routers.{{.ServiceName}}-health.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-health.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-health.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-health.priority=120"
      - "traefik.http.routers.{{.ServiceName}}-health.middlewares=rate-limit,{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # API routes (behind {{.QAGateMiddleware}})
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-api.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `) && PathPrefix(` + "`" + `/api` + "`" + `)"
      - "traefik.http.routers.{{.ServiceName}}-api.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-api.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-api.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-api.priority=90"
      - "traefik.http.routers.{{.ServiceName}}-api.middlewares=rate-limit,{{.QAGateMiddleware}},{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # MCP transport (public — Bearer/OAuth auth handled by app)
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-transport.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `) && PathPrefix(` + "`" + `{{.MCPPath}}` + "`" + `)"
      - "traefik.http.routers.{{.ServiceName}}-transport.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-transport.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-transport.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-transport.priority=100"
      - "traefik.http.routers.{{.ServiceName}}-transport.middlewares=rate-limit,{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # OAuth discovery (public — server-to-server)
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-oauth.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `) && (PathPrefix(` + "`" + `/.well-known` + "`" + `) || Path(` + "`" + `/token` + "`" + `) || Path(` + "`" + `/register` + "`" + `))"
      - "traefik.http.routers.{{.ServiceName}}-oauth.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-oauth.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-oauth.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-oauth.priority=110"
      - "traefik.http.routers.{{.ServiceName}}-oauth.middlewares=rate-limit,{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # OAuth authorize (behind {{.QAGateMiddleware}} — human PIN entry)
      # -----------------------------------------------------------------------
      - "traefik.http.routers.{{.ServiceName}}-authorize.rule=Host(` + "`" + `{{.Hostname}}` + "`" + `) && Path(` + "`" + `/authorize` + "`" + `)"
      - "traefik.http.routers.{{.ServiceName}}-authorize.entrypoints=websecure"
      - "traefik.http.routers.{{.ServiceName}}-authorize.tls.certresolver={{.CertResolver}}"
      - "traefik.http.routers.{{.ServiceName}}-authorize.service={{.ServiceName}}"
      - "traefik.http.routers.{{.ServiceName}}-authorize.priority=110"
      - "traefik.http.routers.{{.ServiceName}}-authorize.middlewares=rate-limit,{{.QAGateMiddleware}},{{.SecurityMiddleware}}"

      # -----------------------------------------------------------------------
      # Security headers
      # -----------------------------------------------------------------------
      - "traefik.http.middlewares.{{.SecurityMiddleware}}.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.{{.SecurityMiddleware}}.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.{{.SecurityMiddleware}}.headers.contentTypeNosniff=true"
      - "traefik.http.middlewares.{{.SecurityMiddleware}}.headers.frameDeny=true"
      - "traefik.http.middlewares.{{.SecurityMiddleware}}.headers.browserXssFilter=true"
`

// GenerateTraefikLabels renders the Traefik docker-compose labels for an MCP
// server deployment. The returned string is ready to paste into a
// docker-compose.yml service definition.
func GenerateTraefikLabels(cfg TraefikConfig) (string, error) {
	if err := validateTraefikConfig(cfg); err != nil {
		return "", err
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.MCPPath == "" {
		cfg.MCPPath = "/mcp"
	}
	if cfg.SecurityMiddleware == "" {
		cfg.SecurityMiddleware = cfg.ServiceName + "-security"
	}
	if cfg.QAGateMiddleware == "" {
		cfg.QAGateMiddleware = "qa-gate"
	}
	if cfg.CertResolver == "" {
		cfg.CertResolver = "letsencrypt"
	}

	t, err := template.New("traefik").Parse(traefikTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}
