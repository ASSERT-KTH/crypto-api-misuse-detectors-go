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

// Add a new function to write metadata
func writeMetadata(vuln Vulnerability, repo Repo, vp VulPackage, pkgNum int, baseName string) error {
	metadata := struct {
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
	}{
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

	outputDir := fmt.Sprintf("./data/analysis/cve/%s/%s-%d-%d",
		baseName,
		strings.ReplaceAll(vuln.Repo.RepoSlug, "/", "-"),
		vuln.ID,
		pkgNum)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Write metadata to file
	metadataJson, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	metadataPath := filepath.Join(outputDir, "vulnerability_info.json")
	if err := os.WriteFile(metadataPath, metadataJson, 0644); err != nil {
		return fmt.Errorf("writing metadata file: %w", err)
	}

	return nil
}

func GenerateCompose(filepath string, outputFile string) error {
	// Extract just the filename without the full path and .json extension
	filename := filepath
	if lastSlash := strings.LastIndex(filepath, "/"); lastSlash >= 0 {
		filename = filepath[lastSlash+1:]
	}
	baseName := strings.TrimSuffix(filename, ".json")

	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Parse JSON
	var vulnerabilities []Vulnerability
	if err := json.Unmarshal(data, &vulnerabilities); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	// Generate Docker Compose YAML
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
			if err := writeMetadata(vuln, vuln.Repo, vp, pkgNum, baseName); err != nil {
				return fmt.Errorf("writing metadata for %s-%d-%d: %w",
					vuln.Repo.RepoSlug, vuln.ID, pkgNum, err)
			}

			latestTag := vp.VulGitTags[len(vp.VulGitTags)-1]

			sb.WriteString(fmt.Sprintf("  id%d-%d:\n", vuln.ID, pkgNum))
			sb.WriteString("    build:\n")
			sb.WriteString("      context: .\n")
			sb.WriteString(fmt.Sprintf("      args:\n        REPO_URL: \"https://%s\"\n", vuln.Repo.RepoSlug))
			sb.WriteString(fmt.Sprintf("        VUL_TAG: \"%s\"\n", latestTag))
			sb.WriteString(fmt.Sprintf("        GO_VERSION: \"%s\"\n", vp.GoVersion))
			sb.WriteString(fmt.Sprintf("    container_name: %s-%d-%d\n", strings.ReplaceAll(vuln.Repo.RepoSlug, "/", "-"), vuln.ID, pkgNum))
			sb.WriteString("    volumes:\n")
			sb.WriteString("      - gopher-shared:/analysis/gopher\n")
			sb.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/data/analysis/cve/%s/%s-%d-%d:/analysis/repo/scan_results\"\n",
				baseName,
				strings.ReplaceAll(vuln.Repo.RepoSlug, "/", "-"),
				vuln.ID,
				pkgNum))
		}
	}

	sb.WriteString("\nvolumes:\n")
	sb.WriteString("  gopher-shared:\n")
	sb.WriteString("    driver: local\n")
	sb.WriteString("    driver_opts:\n")
	sb.WriteString("      type: none\n")
	sb.WriteString("      device: ${BASE_DIR}/gopher\n")
	sb.WriteString("      o: bind\n")

	if err := os.WriteFile(outputFile, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
