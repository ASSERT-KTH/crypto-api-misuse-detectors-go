package compose

import (
	"fmt"
	"os"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/parse"
)

// GenerateComposeFile constructs the complete Docker Compose YAML content as a string
func GenerateComposeFile(vulnerabilities []parse.Vulnerability, outputBasePath string) string {
	var composeBuilder strings.Builder
	composeBuilder.WriteString("version: '3.8'\n\n")
	composeBuilder.WriteString("services:\n")

	for _, vulnerability := range vulnerabilities {
		addVulnerabilityServices(&composeBuilder, vulnerability, outputBasePath)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addVulnerabilityServices adds all services for a single vulnerability to the compose file
func addVulnerabilityServices(builder *strings.Builder, vulnerability parse.Vulnerability, outputBasePath string) {
	// Create a metadata writer for this vulnerability
	metadataWriter := NewMetadataWriter(outputBasePath)

	for packageIndex, vulnPackage := range vulnerability.VulPackages {
		// Skip packages with no identified vulnerable git tags
		if len(vulnPackage.VulGitTags) == 0 {
			continue
		}
		// Set default Go version if not specified
		if vulnPackage.GoVersion == "" {
			vulnPackage.GoVersion = "1.11"
		}

		// Write a metadata file for this vulnerability package
		packageNum := packageIndex + 1
		if err := metadataWriter.WriteMetadata(vulnerability, vulnPackage, packageNum); err != nil {
			// Log error but continue with other packages
			fmt.Fprintf(os.Stderr, "Warning: failed to write metadata for %s-%d-%d: %v\n",
				vulnerability.Repo.RepoSlug, vulnerability.ID, packageNum, err)
			continue
		}

		// Add service configuration to compose file
		serviceConfig := generateServiceConfig(vulnerability, vulnPackage, packageNum, outputBasePath)
		builder.WriteString(serviceConfig)
	}
}

// generateServiceConfig creates the service configuration for a vulnerability
func generateServiceConfig(vulnerability parse.Vulnerability, vulnPackage parse.VulPackage, packageNum int, outputBasePath string) string {
	var serviceBuilder strings.Builder

	// Get the latest vulnerablen git tag
	latestTag := vulnPackage.VulGitTags[len(vulnPackage.VulGitTags)-1]

	// Generate metadata file path for this package
	pkgOutpath := generatePackageAnalysisPath(outputBasePath, vulnerability.Repo.RepoSlug, vulnerability.ID, packageNum)

	// Create container name based on repo and IDs
	containerName := fmt.Sprintf("%s-%d-%d",
		strings.ReplaceAll(vulnerability.Repo.RepoSlug, "/", "-"),
		vulnerability.ID,
		packageNum)

	// Build service configuration
	serviceBuilder.WriteString(fmt.Sprintf("  id%d-%d:\n", vulnerability.ID, packageNum))
	serviceBuilder.WriteString("    build:\n")
	serviceBuilder.WriteString("      context: .\n")
	serviceBuilder.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"https://%s\"\n", vulnerability.Repo.RepoSlug))
	serviceBuilder.WriteString(fmt.Sprintf("        VUL_TAG: \"%s\"\n", latestTag))
	serviceBuilder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", vulnPackage.GoVersion))
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", containerName))
	serviceBuilder.WriteString("    volumes:\n")
	serviceBuilder.WriteString("      - gopher-shared:/analysis/gopher\n")
	serviceBuilder.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/%s:/analysis/repo/scan_results\"\n", pkgOutpath))

	return serviceBuilder.String()
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
