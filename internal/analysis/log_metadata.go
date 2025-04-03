package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VulnerabilityMetadata represents the metadata for a vulnerability
type VulnerabilityMetadata struct {
	ID          int      `json:"id"`
	Package     string   `json:"package"`
	GoVersion   string   `json:"go_version"`
	VulName     string   `json:"vul_name"`
	References  []string `json:"references"`
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
		References:  vuln.References,
		Publish:     vp.Publish,
		CWE:         vuln.CWE,
		CVE:         vuln.CVE,
		Summary:     vp.Summary,
		Level:       vp.Level,
		Score:       vp.Score,
		Remediation: vp.Remediation,
		VulRange:    vp.VulRange,
		VulGitTags:  vp.VulGitTags,
	}
}

// generateMetadataFilePath generates the repository relative directory path for storing a package's analysis results
func generateMetadataFilePath(baseName string, repoSlug string, id int, pkgNum int) string {
	return fmt.Sprintf("data/analysis/cve/%s/%s-%d-%d",
		baseName,
		strings.ReplaceAll(repoSlug, "/", "-"),
		id,
		pkgNum)
}

func writeMetadata(vuln Vulnerability, vp VulPackage, pkgNum int, baseName string) error {
	metadata := createMetadata(vuln, vuln.Repo, vp)

	dirPath := generateMetadataFilePath(baseName, vuln.Repo.RepoSlug, vuln.ID, pkgNum)
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
