package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	logger "github.com/ASSERT-KTH/go-cryptoapi/internal/log"
	"github.com/go-playground/validator/v10"
)

type Service struct {
	ServiceName string   `validate:"required"`
	RepoURL     string   `validate:"required"`
	GitTag      string   `validate:"required"`
	GoVersion   string   `validate:"required"`
	Volumes     []string `validate:"required"`
}

func NewService(serviceName, dsResultsDir, repoURL, gitTag, goVersion string) (Service, error) {
	s := Service{
		ServiceName: serviceName,
		RepoURL:     repoURL,
		GitTag:      gitTag,
		GoVersion:   goVersion,
		Volumes: []string{
			"gopher:/analysis/gopher",
			fmt.Sprintf("${BASE_DIR}/%s/%s:/analysis/repo/scan_results", dsResultsDir, serviceName)},
	}

	validate := validator.New()
	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			return Service{}, fmt.Errorf("Field '%s' failed validation: %s\n", err.Field(), err.Tag())
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
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", s.ServiceName))

	// Volume configuration
	serviceBuilder.WriteString("    volumes:\n")
	for _, volume := range s.Volumes {
		serviceBuilder.WriteString(fmt.Sprintf("      - %s\n", volume))
	}

	return serviceBuilder.String()
}

// Creates service instances from vulnerabilities or modules
type ServiceBuilder struct {
	ResultsDir string
}

func NewServiceBuilder(resultsDir string) *ServiceBuilder {
	return &ServiceBuilder{ResultsDir: resultsDir}
}

func (sb *ServiceBuilder) FromVulnerability(vuln dataset.Vulnerability, pkg dataset.VulPackage, serviceName string) (Service, error) {
	if err := logger.NewMetadataWriter(sb.ResultsDir).WriteVulMetadata(vuln, pkg, serviceName); err != nil {
		fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
	}
	return NewService(serviceName, sb.ResultsDir, vuln.Repo.URL, pkg.GitTag, pkg.GoVersion)
}

func (sb *ServiceBuilder) FromModule(mod dataset.Module, serviceName string) (Service, error) {
	if err := logger.NewMetadataWriter(sb.ResultsDir).WriteModuleMetadata(mod, serviceName); err != nil {
		fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
	}
	return NewService(serviceName, sb.ResultsDir, mod.URL, mod.ReleaseTag, mod.GoVersion)
}
