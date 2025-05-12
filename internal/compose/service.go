// Package compose provides functionality for generating Docker Compose services
// for static analysis tools. It handles both vulnerability analysis and module
// analysis through the Service and ServiceBuilder types.
package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
	"github.com/go-playground/validator/v10"
)

const (
	HostResultsDir = "${BASE_DIR}/results"
)

// Service represents a single Docker Compose service configuration
type Service struct {
	// Container configuration
	ContainerName string    `validate:"required"` // Name of the container and service
	Tool          sast.Tool `validate:"required"` // Analysis tool to use

	// Repository configuration
	RepoURL   string `validate:"required,url"` // URL of the repository to analyze
	GitTag    string `validate:"required"`     // Git tag/version to analyze
	GoVersion string `validate:"required"`     // Go version to use

	// Volume mount configuration for results
	HostResultsPath      string `validate:"required"` // Path on host where results will be stored (${BASE_DIR}/...)
	ContainerResultsPath string `validate:"required"` // Path in container where results will be mounted (/analysis/...)
}

// NewService creates a new Service instance
func NewService(repoID, repoURL, gitTag, goVersion string, tool sast.Tool) (Service, error) {
	toolConfig := tool.GetDockerConfig()
	containerName := fmt.Sprintf("%s-%s", repoID, tool.Name())

	s := Service{
		ContainerName:        containerName,
		Tool:                 tool,
		RepoURL:              repoURL,
		GitTag:               gitTag,
		GoVersion:            goVersion,
		HostResultsPath:      filepath.Join(HostResultsDir, repoID, tool.Name()),
		ContainerResultsPath: toolConfig.ResultsDir,
	}

	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return Service{}, err
	}
	return s, nil
}

// GenerateStr generates the Docker Compose YAML for the service
func (s *Service) GenerateStr() string {
	var builder strings.Builder
	toolConfig := s.Tool.GetDockerConfig()

	// Service name and basic config
	builder.WriteString(fmt.Sprintf("  %s:\n", s.ContainerName))
	builder.WriteString("    build:\n")
	builder.WriteString("      context: .\n")
	builder.WriteString("      args:\n")
	builder.WriteString(fmt.Sprintf("        REPO_URL: \"%s\"\n", s.RepoURL))
	builder.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", s.GitTag))
	builder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", s.GoVersion))
	builder.WriteString(fmt.Sprintf("    container_name: %s\n", s.ContainerName))

	// Volumes
	builder.WriteString("    volumes:\n")
	builder.WriteString(fmt.Sprintf("      - %s\n", toolConfig.VolumeAttribute))
	builder.WriteString(fmt.Sprintf("      - %s:%s\n", s.HostResultsPath, s.ContainerResultsPath))

	// Command
	// builder.WriteString("    command:\n")
	// builder.WriteString(fmt.Sprintf("      - %s\n", toolConfig.Command))

	builder.WriteString("    command:\n")
	for _, part := range toolConfig.Command {
		builder.WriteString(fmt.Sprintf("      - %s\n", part))
	}

	return builder.String()
}

// ServiceBuilder helps create Service instances for different analysis types.
// It manages the creation of services for both vulnerability and module analysis,
// handling the common configuration needed for each type of analysis.
type ServiceBuilder struct {
	Tools []sast.Tool // Analysis tools to use for each service
}

// NewServiceBuilder creates a new ServiceBuilder with the given tools
func NewServiceBuilder(tools []sast.Tool) *ServiceBuilder {
	return &ServiceBuilder{
		Tools: tools,
	}
}

// FromVulnerability creates services for analyzing a vulnerability.
// Returns an error if any service creation fails, rather than skipping errors.
func (sb *ServiceBuilder) FromVulnerability(vuln dataset.Vulnerability, pkg dataset.VulPackage, baseName string) ([]Service, error) {
	var services []Service
	var errs []error

	for _, tool := range sb.Tools {
		service, err := NewService(baseName, vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, tool)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create service %s (%s): %w", baseName, tool.Name(), err))
			continue
		}
		services = append(services, service)
	}

	if len(errs) > 0 {
		return services, fmt.Errorf("encountered %d errors creating services: %v", len(errs), errs)
	}
	return services, nil
}

// FromModule creates services for analyzing a module.
// Returns an error if any service creation fails, rather than skipping errors.
func (sb *ServiceBuilder) FromModule(mod dataset.Module, baseName string) ([]Service, error) {
	var services []Service
	var errs []error

	for _, tool := range sb.Tools {
		service, err := NewService(baseName, mod.URL, mod.ReleaseTag, mod.GoVersion, tool)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create service %s (%s): %w", baseName, tool.Name(), err))
			continue
		}
		services = append(services, service)
	}

	if len(errs) > 0 {
		return services, fmt.Errorf("encountered %d errors creating services: %v", len(errs), errs)
	}
	return services, nil
}

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
