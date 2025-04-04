package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		want     string
	}{
		{
			name:     "simple filename",
			filepath: "vulnerabilities.json",
			want:     "vulnerabilities",
		},
		{
			name:     "with path",
			filepath: "/path/to/vulnerabilities_conservative.json",
			want:     "vulnerabilities_conservative",
		},
		{
			name:     "without extension",
			filepath: "vulnerabilities",
			want:     "vulnerabilities",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFileName(tt.filepath)
			if got != tt.want {
				t.Errorf("extractBaseName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMetadataPath(t *testing.T) {
	tests := []struct {
		name     string
		baseName string
		repoSlug string
		id       int
		pkgNum   int
		want     string
	}{
		{
			name:     "simple path",
			baseName: "vulnerabilities",
			repoSlug: "github.com/test/repo",
			id:       1,
			pkgNum:   2,
			want:     "data/analysis/cve/vulnerabilities/github.com-test-repo-1-2",
		},
		{
			name:     "with special characters",
			baseName: "vuln_conservative",
			repoSlug: "github.com/org/repo-name",
			id:       123,
			pkgNum:   1,
			want:     "data/analysis/cve/vuln_conservative/github.com-org-repo-name-123-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generatePackageAnalysisPath(tt.baseName, tt.repoSlug, tt.id, tt.pkgNum)
			if got != tt.want {
				t.Errorf("getMetadataPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateServiceConfig(t *testing.T) {
	vuln := Vulnerability{
		ID: 1,
		Repo: Repository{
			RepoSlug: "github.com/test/repo",
		},
	}

	vp := VulPackage{
		GoVersion:  "1.16",
		VulGitTags: []string{"v0.9.0", "v1.0.0"},
	}

	config := generateServiceConfig(vuln, vp, 1, "test")
	expectedStrings := []string{
		"id1-1:",
		"REPO_URL: \"https://github.com/test/repo\"",
		"VUL_TAG: \"v1.0.0\"",
		"GO_VERSION: \"1.16\"",
		"container_name: github.com-test-repo-1-1",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(config, expected) {
			t.Errorf("generateServiceConfig() missing expected string: %s", expected)
		}
	}
}

func TestReadVulnerabilities(t *testing.T) {
	// Create a temporary test file
	testJSON := `[{
		"id": 1,
		"repo": {
			"repo_slug": "github.com/test/repo",
			"cve": "CVE-2023-1234"
		},
		"vul_packages": [{
			"name": "test-pkg",
			"vul_git_tags": ["v1.0.0"],
			"go_version": "1.16"
		}]
	}]`

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.json")
	if err := os.WriteFile(tmpFile, []byte(testJSON), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	vulns, err := readVulnerabilities(tmpFile)
	if err != nil {
		t.Fatalf("readVulnerabilities() error = %v", err)
	}

	if len(vulns) != 1 {
		t.Errorf("readVulnerabilities() got %d vulnerabilities, want 1", len(vulns))
	}

	if vulns[0].ID != 1 || vulns[0].Repo.RepoSlug != "github.com/test/repo" {
		t.Errorf("readVulnerabilities() got unexpected vulnerability data")
	}
}
