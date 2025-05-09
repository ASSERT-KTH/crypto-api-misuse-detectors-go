package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	logger "github.com/ASSERT-KTH/go-cryptoapi/internal/log"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
	"github.com/go-playground/validator/v10"
)

type Service struct {
	ServiceName string    `validate:"required"`
	RepoURL     string    `validate:"required"`
	GitTag      string    `validate:"required"`
	GoVersion   string    `validate:"required"`
	Tool        sast.Tool `validate:"required"`
}

func NewService(serviceName, dsResultsDir, repoURL, gitTag, goVersion string, tool sast.Tool) (Service, error) {
	s := Service{
		ServiceName: serviceName,
		RepoURL:     repoURL,
		GitTag:      gitTag,
		GoVersion:   goVersion,
		Tool:        tool,
	}

	validate := validator.New()
	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			return Service{}, fmt.Errorf("field '%s' failed validation: %s\n", err.Field(), err.Tag())
		}
	}
	return s, nil
}

func (s *Service) GenerateStr() string {
	var serviceBuilder strings.Builder

	serviceBuilder.WriteString(fmt.Sprintf("  %s:\n", s.ServiceName))

	// Build configuration
	serviceBuilder.WriteString("    build:\n")
	serviceBuilder.WriteString("      context: .\n")
	serviceBuilder.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"%s\"\n", s.RepoURL))
	serviceBuilder.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", s.GitTag))
	serviceBuilder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", s.GoVersion))

	// Container name
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", s.ServiceName))

	// Volumes from tool config
	serviceBuilder.WriteString("    volumes:\n")

	// Add tool volumes and output directory
	config := s.Tool.GetDockerConfig()
	serviceBuilder.WriteString(fmt.Sprintf("      - %s\n", config.Volumes))
	if config.OutputDir != "" {
		serviceBuilder.WriteString(fmt.Sprintf("      - ${BASE_DIR}/%s:%s\n",
			s.ServiceName, config.OutputDir))
	}

	// Command from tool config
	serviceBuilder.WriteString("    command:\n")
	serviceBuilder.WriteString(fmt.Sprintf("      - %s\n", config.Command))
	return serviceBuilder.String()
}

// Creates service instances from vulnerabilities or modules
type ServiceBuilder struct {
	ResultsDir string
	Tools      []sast.Tool
}

func NewServiceBuilder(resultsDir string, tools []sast.Tool) *ServiceBuilder {
	return &ServiceBuilder{
		ResultsDir: resultsDir,
		Tools:      tools,
	}
}

func (sb *ServiceBuilder) FromVulnerability(vuln dataset.Vulnerability, pkg dataset.VulPackage, baseServiceName string) ([]Service, error) {
	var services []Service
	for _, tool := range sb.Tools {
		serviceName := fmt.Sprintf("%s-%s", baseServiceName, tool.Name())
		if err := logger.NewMetadataWriter(sb.ResultsDir).WriteVulMetadata(vuln, pkg, serviceName); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
			continue
		}

		service, err := NewService(serviceName, sb.ResultsDir, vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, tool)
		if err != nil {
			fmt.Printf("Warning: failed to create service for %s: %v\n", serviceName, err)
			continue
		}
		services = append(services, service)
	}
	return services, nil
}

func (sb *ServiceBuilder) FromModule(mod dataset.Module, baseServiceName string) ([]Service, error) {
	var services []Service
	for _, tool := range sb.Tools {
		serviceName := fmt.Sprintf("%s-%s", baseServiceName, tool.Name())
		if err := logger.NewMetadataWriter(sb.ResultsDir).WriteModuleMetadata(mod, serviceName); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
			continue
		}

		service, err := NewService(serviceName, sb.ResultsDir, mod.URL, mod.ReleaseTag, mod.GoVersion, tool)
		if err != nil {
			fmt.Printf("Warning: failed to create service for %s: %v\n", serviceName, err)
			continue
		}
		services = append(services, service)
	}
	return services, nil
}

func generateServiceName(repoURL string, ID string) (string, error) {
	validator := validator.New()
	if err := validator.Var(repoURL, "required,url"); err != nil {
		return "", fmt.Errorf("Invalid repo URL: %s\n", err)
	}

	cleanPrefix := strings.TrimPrefix(strings.TrimPrefix(repoURL, "https://"), "http://")
	cleanURL := strings.ReplaceAll(cleanPrefix, "/", "-")
	serviceName := cleanURL
	if ID != "" {
		serviceName += "-" + ID
	}
	return strings.ToLower(serviceName), nil
}
