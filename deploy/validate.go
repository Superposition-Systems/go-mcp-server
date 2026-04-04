package deploy

import (
	"fmt"
	"regexp"
)

var (
	validName      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
	validHostname  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
	validPath      = regexp.MustCompile(`^/[a-zA-Z0-9/._-]*$`)
	validPort      = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	validGoVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
)

func validateTraefikConfig(cfg TraefikConfig) error {
	if cfg.ServiceName == "" {
		return fmt.Errorf("ServiceName is required")
	}
	if !validName.MatchString(cfg.ServiceName) {
		return fmt.Errorf("ServiceName contains invalid characters: %q", cfg.ServiceName)
	}
	if cfg.Hostname == "" {
		return fmt.Errorf("Hostname is required")
	}
	if !validHostname.MatchString(cfg.Hostname) {
		return fmt.Errorf("Hostname contains invalid characters: %q", cfg.Hostname)
	}
	if cfg.Port != "" && !validPort.MatchString(cfg.Port) {
		return fmt.Errorf("Port contains invalid characters: %q", cfg.Port)
	}
	if cfg.MCPPath != "" && !validPath.MatchString(cfg.MCPPath) {
		return fmt.Errorf("MCPPath contains invalid characters: %q", cfg.MCPPath)
	}
	if cfg.SecurityMiddleware != "" && !validName.MatchString(cfg.SecurityMiddleware) {
		return fmt.Errorf("SecurityMiddleware contains invalid characters: %q", cfg.SecurityMiddleware)
	}
	if cfg.QAGateMiddleware != "" && !validName.MatchString(cfg.QAGateMiddleware) {
		return fmt.Errorf("QAGateMiddleware contains invalid characters: %q", cfg.QAGateMiddleware)
	}
	if cfg.CertResolver != "" && !validName.MatchString(cfg.CertResolver) {
		return fmt.Errorf("CertResolver contains invalid characters: %q", cfg.CertResolver)
	}
	return nil
}

func validateDockerfileConfig(cfg DockerfileConfig) error {
	if cfg.BinaryName == "" {
		return fmt.Errorf("BinaryName is required")
	}
	if !validName.MatchString(cfg.BinaryName) {
		return fmt.Errorf("BinaryName contains invalid characters: %q", cfg.BinaryName)
	}
	if cfg.GoVersion != "" && !validGoVersion.MatchString(cfg.GoVersion) {
		return fmt.Errorf("GoVersion contains invalid characters: %q", cfg.GoVersion)
	}
	if cfg.Port != "" && !validPort.MatchString(cfg.Port) {
		return fmt.Errorf("Port contains invalid characters: %q", cfg.Port)
	}
	return nil
}
