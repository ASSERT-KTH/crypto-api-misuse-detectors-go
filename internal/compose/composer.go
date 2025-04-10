package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

type Composer interface {
	// GenerateComposeStr constructs the complete Docker Compose YAML content as a string
	GenerateComposeStr() string
}

// CreateComposer is a factory function that creates the appropriate composer based on dataset type
func CreateComposer(ds dataset.Dataset) (Composer, error) {
	switch ds.Type() {
	case dataset.VulnerabilityDatasetType:
		vulDataset, ok := ds.(*dataset.VulnerabilityDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *VulnerableModuleDataset, got %T", ds)
		}
		return &VulComposer{Dataset: vulDataset, MetadataWriter: NewMetadataWriter(ds.GetDatasetIdentifier())}, nil
	case dataset.ModuleDatasetType:
		modDataset, ok := ds.(*dataset.ModuleDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *ModuleDataset, got %T", ds)
		}
		return &ModComposer{Dataset: modDataset}, nil
	default:
		return nil, fmt.Errorf("unknown dataset type: %s", ds.Type())
	}
}

// generateVolumeConfig creates the volume configuration
func generateVolumeConfig() string {
	return `
volumes:
  gopher-shared:
    driver: local
    driver_opts:
      type: none
      device: ${BASE_DIR}/gopher
      o: bind
`
}

// generateComposeHeader creates the common header for all compose files
func generateComposeHeader() string {
	return "version: '3.8'\n\nservices:\n"
}

// TODO needs refactoring...
// generateServiceConfigVul creates the service configuration for specified package/module
func generateServiceStr(URL string, gitTag string, goVersion string, serviceName string, resultsDir string) string {
	var serviceBuilder strings.Builder

	// Build service configuration
	serviceBuilder.WriteString(fmt.Sprintf("  %s:\n", serviceName))
	serviceBuilder.WriteString("    build:\n")
	serviceBuilder.WriteString("      context: .\n")
	serviceBuilder.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"%s\"\n", URL))
	serviceBuilder.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", gitTag))
	serviceBuilder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", goVersion))
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", serviceName))
	serviceBuilder.WriteString("    volumes:\n")
	serviceBuilder.WriteString("      - gopher-shared:/analysis/gopher\n")
	serviceBuilder.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/%s:/analysis/repo/scan_results\"\n", resultsDir))

	return serviceBuilder.String()
}

func generateServiceName(nameOrSlug string, id string) string {
	repoName := strings.TrimPrefix(nameOrSlug, "github.com/")
	return fmt.Sprintf("%s-%s",
		strings.ReplaceAll(repoName, "/", "-"),
		id)
}

// generateResultsPath generates the repository relative directory path for storing a package's analysis results
func generateResultsPath(baseName string, containerName string) string {
	return fmt.Sprintf("data/analysis/%s/%s",
		baseName,
		containerName)
}
