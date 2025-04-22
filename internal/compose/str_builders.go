package compose

import (
	"fmt"
	"strings"
)

// generateComposeHeader creates the common header for all compose files
func generateComposeHeader() string {
	return "version: '3.8'\n\nservices:\n"
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

// generateServiceStr creates a service configuration string for Docker Compose
func generateServiceStr(repoURL, gitTag, goVersion, serviceName string, analysisDir string) string {
	var serviceBuilder strings.Builder

	// Service name
	serviceBuilder.WriteString(fmt.Sprintf("  %s:\n", serviceName))

	// Build configuration
	serviceBuilder.WriteString("    build:\n")
	serviceBuilder.WriteString("      context: .\n")
	serviceBuilder.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"%s\"\n", repoURL))
	serviceBuilder.WriteString(fmt.Sprintf("        GIT_TAG: \"%s\"\n", gitTag))
	serviceBuilder.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", goVersion))
	serviceBuilder.WriteString(fmt.Sprintf("    container_name: %s\n", serviceName))

	// Volume configuration
	serviceBuilder.WriteString("    volumes:\n")
	serviceBuilder.WriteString("      - gopher-shared:/analysis/gopher\n")
	serviceBuilder.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/%s:/analysis/repo/scan_results\"\n", analysisDir))

	return serviceBuilder.String()
}

// generateServiceName creates a unique service name
func generateServiceName(repoSlug string, ID string) string {
	// Remove github.com/ prefix if present
	repoName := strings.TrimPrefix(repoSlug, "github.com/")

	// Create a unique service name using repo and id
	serviceName := fmt.Sprintf("%s-%s",
		strings.ReplaceAll(repoName, "/", "-"),
		ID)

	return strings.ToLower(serviceName)
}
