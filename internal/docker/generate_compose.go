package dataset

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type VulPackage struct {
	Name       string   `json:"name"`
	VulGitTags []string `json:"vul_git_tags"`
	GoVersion  string   `json:"go_version"`
}

type Repo struct {
	RepoSlug string   `json:"repo_slug"`
	GitTags  []string `json:"git_tags"`
}

type Vulnerability struct {
	ID          int          `json:"id"`
	Repo        Repo         `json:"repo"`
	VulPackages []VulPackage `json:"vul_packages"`
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
			sb.WriteString(fmt.Sprintf("      - \"${BASE_DIR}/results/%s/%s-%d-%d:/analysis/repo/scan_results\"\n",
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
