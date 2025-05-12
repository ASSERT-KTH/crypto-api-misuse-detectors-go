// Package compose provides functionality for generating Docker Compose services
// for static analysis tools. It handles both vulnerability analysis and module
// analysis through the Service and ServiceBuilder types.
package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
	"github.com/go-playground/validator/v10"
)

// Service represents a single Docker Compose service configuration
type Service struct {
	// Container configuration
	Name string    `validate:"required"` // Name of the container and service
	Tool sast.Tool `validate:"required"` // Analysis tool to use

	// Repository configuration
	RepoURL   string `validate:"required,url"` // URL of the repository to analyze
	GitTag    string `validate:"required"`     // Git tag/version to analyze
	GoVersion string `validate:"required"`     // Go version to use

	// Path configuration
	Paths ServicePaths `validate:"required"` // Path configuration for this service
}

// ServiceBuilder helps create Service instances for different analysis types
type ServiceBuilder struct {
	Tools  []sast.Tool // Analysis tools to use for each service
	Config Config      // Configuration including results directory structure
}

// NewServiceBuilder creates a new ServiceBuilder with the given tools
func NewServiceBuilder(tools []sast.Tool, config Config) *ServiceBuilder {
	return &ServiceBuilder{
		Tools:  tools,
		Config: config,
	}
}

// NewService creates a new Service instance
func NewService(repoID, repoURL, gitTag, goVersion string, tool sast.Tool, cfg Config) (Service, error) {
	svcName := fmt.Sprintf("%s-%s", repoID, tool.Name())

	// Create path configuration for this service
	paths := NewServicePaths(DefaultPaths(), DefaultContainerPaths(), cfg.DatasetDir, repoID, tool.Name())

	svc := Service{
		Name:      svcName,
		Tool:      tool,
		RepoURL:   repoURL,
		GitTag:    gitTag,
		GoVersion: goVersion,
		Paths:     paths,
	}

	validate := validator.New()
	if err := validate.Struct(svc); err != nil {
		return Service{}, err
	}
	return svc, nil
}

// FromVulnerability creates services for analyzing a vulnerability
func (sb *ServiceBuilder) FromVulnerability(vuln dataset.Vulnerability, pkg dataset.VulPackage, baseName string) ([]Service, error) {
	var svcs []Service
	var errs []error

	for _, tool := range sb.Tools {
		svc, err := NewService(baseName, vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, tool, sb.Config)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create service %s (%s): %w", baseName, tool.Name(), err))
			continue
		}
		svcs = append(svcs, svc)
	}

	if len(errs) > 0 {
		return svcs, fmt.Errorf("encountered %d errors creating services: %v", len(errs), errs)
	}
	return svcs, nil
}

// FromModule creates services for analyzing a module
func (sb *ServiceBuilder) FromModule(mod dataset.Module, baseName string) ([]Service, error) {
	var svcs []Service
	var errs []error

	for _, tool := range sb.Tools {
		svc, err := NewService(baseName, mod.URL, mod.ReleaseTag, mod.GoVersion, tool, sb.Config)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create service %s (%s): %w", baseName, tool.Name(), err))
			continue
		}
		svcs = append(svcs, svc)
	}

	if len(errs) > 0 {
		return svcs, fmt.Errorf("encountered %d errors creating services: %v", len(errs), errs)
	}
	return svcs, nil
}

// GenerateStr generates the Docker Compose YAML for the service
func (s *Service) GenerateStr() string {
	var buf strings.Builder
	toolCfg := s.Tool.GetDockerConfig()

	buf.WriteString(fmt.Sprintf("  %s:\n", s.Name))
	buf.WriteString(s.generateServiceConfig())
	buf.WriteString(s.generateVolumeMounts(toolCfg))
	buf.WriteString(s.generateCommand(toolCfg))

	return buf.String()
}

// generateServiceConfig generates the basic service configuration
func (s *Service) generateServiceConfig() string {
	var buf strings.Builder
	buf.WriteString("    build:\n")
	buf.WriteString("      context: .\n")
	buf.WriteString("      args:\n")
	buf.WriteString(fmt.Sprintf("        REPO_URL: \"%s\"\n", s.RepoURL))
	buf.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", s.GitTag))
	buf.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", s.GoVersion))
	buf.WriteString(fmt.Sprintf("    container_name: %s\n", s.Name))
	return buf.String()
}

// generateVolumeMounts generates the volume mount configuration
func (s *Service) generateVolumeMounts(toolCfg sast.DockerConfig) string {
	var buf strings.Builder
	buf.WriteString("    volumes:\n")
	buf.WriteString(fmt.Sprintf("      - %s\n", toolCfg.VolumeAttribute))
	buf.WriteString(fmt.Sprintf("      - %s:%s\n", s.Paths.HostResultsPath, s.Paths.ContainerResultsPath))

	return buf.String()
}

// generateCommand generates the command configuration
func (s *Service) generateCommand(toolCfg sast.DockerConfig) string {
	var buf strings.Builder
	buf.WriteString("    command:\n")
	for _, cmd := range toolCfg.Command {
		buf.WriteString(fmt.Sprintf("      - %s\n", cmd))
	}
	return buf.String()
}

// Helper functions

// generateServiceName creates a valid service name from a repo URL and identifier
func generateServiceName(repoURL, id string) (string, error) {
	cleanPrefix := strings.TrimPrefix(strings.TrimPrefix(repoURL, "https://"), "http://")
	cleanURL := strings.ReplaceAll(cleanPrefix, "/", "-")

	name := strings.ToLower(cleanURL)
	if id != "" {
		name += "-" + strings.ToLower(id)
	}
	return name, nil
}
