package docker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type VulPackage struct {
	Name        string   `json:"name"`
	Publish     string   `json:"publish"`
	VulName     string   `json:"vul_name"`
	VulRange    string   `json:"vul_range"`
	Level       string   `json:"level"`
	Score       string   `json:"score"`
	Remediation string   `json:"remediation_description"`
	Summary     string   `json:"summary"`
	VulGitTags  []string `json:"vul_git_tags"`
	GoVersion   string   `json:"go_version"`
}

type Repo struct {
	RepoSlug   string   `json:"repo_slug"`
	GitTags    []string `json:"git_tags"`
	References []string `json:"references"`
	CVE        string   `json:"cve"`
	CWE        string   `json:"cwe"`
}

type Vulnerability struct {
	ID          int          `json:"id"`
	Repo        Repo         `json:"repo"`
	VulPackages []VulPackage `json:"vul_packages"`
}

// VulnerabilityMetadata represents the metadata for a vulnerability
type VulnerabilityMetadata struct {
	ID          int      `json:"id"`
	Package     string   `json:"package"`
	GoVersion   string   `json:"go_version"`
	VulName     string   `json:"vul_name"`
	Publish     string   `json:"publish"`
	CWE         string   `json:"cwe"`
	CVE         string   `json:"cve"`
	Summary     string   `json:"summary"`
	Level       string   `json:"level"`
	Score       string   `json:"score"`
	Remediation string   `json:"remediation_description"`
	VulRange    string   `json:"vul_range"`
	VulGitTags  []string `json:"vul_git_tags"`
}

// createMetadata creates a metadata struct from vulnerability info
func createMetadata(vuln Vulnerability, repo Repo, vp VulPackage) VulnerabilityMetadata {
	return VulnerabilityMetadata{
		ID:          vuln.ID,
		Package:     vp.Name,
		GoVersion:   vp.GoVersion,
		VulName:     vp.VulName,
		Publish:     vp.Publish,
		CWE:         repo.CWE,
		CVE:         repo.CVE,
		Summary:     vp.Summary,
		Level:       vp.Level,
		Score:       vp.Score,
		Remediation: vp.Remediation,
		VulRange:    vp.VulRange,
		VulGitTags:  vp.VulGitTags,
	}
}

// getMetadataPath generates the path for metadata files
func getMetadataPath(baseName string, repoSlug string, id int, pkgNum int) string {
	return fmt.Sprintf("data/analysis/cve/%s/%s-%d-%d",
		baseName,
		strings.ReplaceAll(repoSlug, "/", "-"),
		id,
		pkgNum)
}

func writeMetadata(vuln Vulnerability, vp VulPackage, pkgNum int, baseName string) error {
	metadata := createMetadata(vuln, vuln.Repo, vp)

	dirPath := getMetadataPath(baseName, vuln.Repo.RepoSlug, vuln.ID, pkgNum)
	dirPath = fmt.Sprintf("./%s", dirPath)
	metadataPath := filepath.Join(dirPath, "vulnerability_info.json")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Write metadata to file
	metadataJson, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataJson, 0644); err != nil {
		return fmt.Errorf("writing metadata file: %w", err)
	}

	return nil
}

// extractBaseName gets the base name from filepath without extension
func extractBaseName(filepath string) string {
	filename := filepath
	if lastSlash := strings.LastIndex(filepath, "/"); lastSlash >= 0 {
		filename = filepath[lastSlash+1:]
	}
	return strings.TrimSuffix(filename, ".json")
}

// readVulnerabilities reads and parses the vulnerabilities from JSON file
func readVulnerabilities(filepath string) ([]Vulnerability, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var vulnerabilities []Vulnerability
	if err := json.Unmarshal(data, &vulnerabilities); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return vulnerabilities, nil
}

// generateServiceConfig creates the service configuration for a vulnerability
func generateServiceConfig(vuln Vulnerability, vp VulPackage, pkgNum int, baseName string) string {
	var sb strings.Builder
	latestTag := vp.VulGitTags[len(vp.VulGitTags)-1]
	resultPath := getMetadataPath(baseName, vuln.Repo.RepoSlug, vuln.ID, pkgNum)

	sb.WriteString(fmt.Sprintf("  id%d-%d:\n", vuln.ID, pkgNum))
	sb.WriteString("    build:\n")
	sb.WriteString("      context: .\n")
	sb.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"https://%s\"\n", vuln.Repo.RepoSlug))
	sb.WriteString(fmt.Sprintf("        VUL_TAG: \"%s\"\n", latestTag))
	sb.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", vp.GoVersion))
	sb.WriteString(fmt.Sprintf("    container_name: %s-%d-%d\n", strings.ReplaceAll(vuln.Repo.RepoSlug, "/", "-"), vuln.ID, pkgNum))
	sb.WriteString("    volumes:\n")
	sb.WriteString("      - gopher-shared:/analysis/gopher\n")
	sb.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/%s:/analysis/repo/scan_results\"\n", resultPath))

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

func GenerateCompose(filepath string, outputFile string) error {
	baseName := extractBaseName(filepath)

	vulnerabilities, err := readVulnerabilities(filepath)
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

	if err := os.WriteFile(outputFile, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
