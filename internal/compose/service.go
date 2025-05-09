package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	logger "github.com/ASSERT-KTH/go-cryptoapi/internal/log"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
	"github.com/go-playground/validator/v10"
)

// Service represents a single Docker Compose service.
type Service struct {
	ContainerName string    `validate:"required"`
	OutputDir     string    `validate:"required"`
	RepoURL       string    `validate:"required"`
	GitTag        string    `validate:"required"`
	GoVersion     string    `validate:"required"`
	Tool          sast.Tool `validate:"required"`
}

// NewService creates a new Service instance.
func NewService(containerName, outputDir, repoURL, gitTag, goVersion string, tool sast.Tool) (Service, error) {
	s := Service{
		ContainerName: containerName,
		OutputDir:     outputDir,
		RepoURL:       repoURL,
		GitTag:        gitTag,
		GoVersion:     goVersion,
		Tool:          tool,
	}

	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return Service{}, err
	}
	return s, nil
}

// GenerateStr generates the Docker Compose YAML for the service.
func (s *Service) GenerateStr() string {
	var serviceBuilder strings.Builder

	serviceBuilder.WriteString(fmt.Sprintf("  %s:\n", s.ContainerName))

	// Build configuration
	serviceBuilder.WriteString("    build:\n")
	serviceBuilder.WriteString("      context: .\n")
	serviceBuilder.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"%s\"\n", s.RepoURL))
	serviceBuilder.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", s.GitTag))
	serviceBuilder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", s.GoVersion))

	// Container name
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", s.ContainerName))

	// Volumes from tool config
	serviceBuilder.WriteString("    volumes:\n")

	// Add tool volumes and output directory
	config := s.Tool.GetDockerConfig()
	if err := sast.ValidateDockerConfig(config); err != nil {
		return fmt.Sprintf("  %s:\n    # Error: %v\n", s.ContainerName, err)
	}
	serviceBuilder.WriteString(fmt.Sprintf("      - %s\n", config.VolumeAttribute))
	if config.OutputDir != "" {
		serviceBuilder.WriteString(fmt.Sprintf("      - ${BASE_DIR}/%s:%s\n",
			s.OutputDir, config.OutputDir))
	}

	// Command from tool config
	serviceBuilder.WriteString("    command:\n")
	serviceBuilder.WriteString(fmt.Sprintf("      - %s\n", config.Command))
	return serviceBuilder.String()
}

// ServiceBuilder helps create Service instances for vulnerabilities or modules.
type ServiceBuilder struct {
	ResultsDir string
	Tools      []sast.Tool
}

// NewServiceBuilder creates a new ServiceBuilder.
func NewServiceBuilder(resultsDir string, tools []sast.Tool) *ServiceBuilder {
	return &ServiceBuilder{
		ResultsDir: resultsDir,
		Tools:      tools,
	}
}

// FromVulnerability creates services for a vulnerability.
func (sb *ServiceBuilder) FromVulnerability(vuln dataset.Vulnerability, pkg dataset.VulPackage, baseServiceName string) ([]Service, error) {
	var services []Service
	for _, tool := range sb.Tools {
		containerName := fmt.Sprintf("%s-%s", baseServiceName, tool.Name())
		outputDir := filepath.Join("vulnerability", baseServiceName, tool.Name())

		if err := logger.NewMetadataWriter(sb.ResultsDir).WriteVulMetadata(vuln, pkg, outputDir); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", outputDir, err)
			continue
		}

		service, err := NewService(containerName, outputDir, vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, tool)
		if err != nil {
			fmt.Printf("Warning: failed to create service for %s: %v\n", containerName, err)
			continue
		}
		services = append(services, service)
	}
	return services, nil
}

// FromModule creates services for a module.
func (sb *ServiceBuilder) FromModule(mod dataset.Module, baseServiceName string) ([]Service, error) {
	var services []Service
	for _, tool := range sb.Tools {
		containerName := fmt.Sprintf("%s-%s", baseServiceName, tool.Name())
		outputDir := filepath.Join("top_starred", baseServiceName, tool.Name())

		if err := logger.NewMetadataWriter(sb.ResultsDir).WriteModuleMetadata(mod, outputDir); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", outputDir, err)
			continue
		}

		service, err := NewService(containerName, outputDir, mod.URL, mod.ReleaseTag, mod.GoVersion, tool)
		if err != nil {
			fmt.Printf("Warning: failed to create service for %s: %v\n", containerName, err)
			continue
		}
		services = append(services, service)
	}
	return services, nil
}

// generateServiceName generates a valid service name from a repo URL and ID.
func generateServiceName(repoURL string, ID string) (string, error) {
	validator := validator.New()
	if err := validator.Var(repoURL, "required,url"); err != nil {
		return "", fmt.Errorf("invalid repo URL: %s", err)
	}

	cleanPrefix := strings.TrimPrefix(strings.TrimPrefix(repoURL, "https://"), "http://")
	cleanURL := strings.ReplaceAll(cleanPrefix, "/", "-")
	serviceName := cleanURL
	if ID != "" {
		serviceName += "-" + ID
	}
	return strings.ToLower(serviceName), nil
}
