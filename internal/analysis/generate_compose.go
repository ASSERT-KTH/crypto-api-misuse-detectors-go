package main

import (
	"fmt"
	"os"
	"strings"
)

// generateServiceConfig creates the service configuration for a vulnerability
func generateServiceConfig(vul Vulnerability, vp VulPackage, pkgNum int, baseName string) string {
	var sb strings.Builder
	latestTag := vp.VulGitTags[len(vp.VulGitTags)-1]
	pkgOutpath := generateMetadataFilePath(baseName, vul.Repo.RepoSlug, vul.ID, pkgNum)

	sb.WriteString(fmt.Sprintf("  id%d-%d:\n", vul.ID, pkgNum))
	sb.WriteString("    build:\n")
	sb.WriteString("      context: .\n")
	sb.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"https://%s\"\n", vul.Repo.RepoSlug))
	sb.WriteString(fmt.Sprintf("        VUL_TAG: \"%s\"\n", latestTag))
	sb.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", vp.GoVersion))
	sb.WriteString(fmt.Sprintf("    container_name: %s-%d-%d\n", strings.ReplaceAll(vul.Repo.RepoSlug, "/", "-"), vul.ID, pkgNum))
	sb.WriteString("    volumes:\n")
	sb.WriteString("      - gopher-shared:/analysis/gopher\n")
	sb.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/%s:/analysis/repo/scan_results\"\n", pkgOutpath))

	return sb.String()
}

// generateVolumeConfig creates the volume configuration
func generateVolumeConfig() string {
	var sb strings.Builder
	sb.WriteString("\nvolumes:\n")
	sb.WriteString("  gopher-shared:\n")
	sb.WriteString("    driver: local\n")
	sb.WriteString("    driver_opts:\n")
	sb.WriteString("      type: none\n")
	sb.WriteString("      device: ${BASE_DIR}/gopher\n")
	sb.WriteString("      o: bind\n")
	return sb.String()
}

// Takes a vulnerability json file as input and generates a docker-compose file (outFilepath).
func GenerateCompose(vulFilepath string, outFilepath string) error {
	baseName := getFileName(vulFilepath)

	vulnerabilities, err := readVulnerabilities(vulFilepath)
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("version: '3.8'\n\n")
	sb.WriteString("services:\n")

	for _, vuln := range vulnerabilities {
		pkgNum := 0
		for _, vp := range vuln.VulPackages {
			pkgNum++
			if len(vp.VulGitTags) == 0 {
				continue
			}
			if vp.GoVersion == "" {
				vp.GoVersion = "1.11"
			}

			// Write metadata for this vulnerability
			if err := writeMetadata(vuln, vp, pkgNum, baseName); err != nil {
				return fmt.Errorf("writing metadata for %s-%d-%d: %w",
					vuln.Repo.RepoSlug, vuln.ID, pkgNum, err)
			}

			sb.WriteString(generateServiceConfig(vuln, vp, pkgNum, baseName))
		}
	}

	sb.WriteString(generateVolumeConfig())

	if err := os.WriteFile(outFilepath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
