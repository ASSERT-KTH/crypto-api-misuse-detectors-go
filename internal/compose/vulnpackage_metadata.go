package compose

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


func writeMetadata(vulnerability Vulnerability, vulnPackage VulPackage, packageNum int, baseFileName string) error {
	// Create metadata struct
	metadata := VulnerabilityMetadata{
		ID:          vulnerability.ID,
		Package:     vulnPackage.Name,
		GoVersion:   vulnPackage.GoVersion,
		VulName:     vulnPackage.VulName,
		References:  vulnerability.References,
		Publish:     vulnPackage.Publish,
		CWE:         vulnerability.CWE,
		CVE:         vulnerability.CVE,
		Summary:     vulnPackage.Summary,
		Level:       vulnPackage.Level,
		Score:       vulnPackage.Score,
		Remediation: vulnPackage.Remediation,
		VulRange:    vulnPackage.VulRange,
		VulGitTags:  vulnPackage.VulGitTags,
	}

	// Generate file path for metadata
	metadataDir := generateMetadataDirectory(baseFileName, vulnerability.Repo.RepoSlug, vulnerability.ID, packageNum)
	metadataFilePath := filepath.Join(metadataDir, "vulnerability_info.json")

	// Ensure the directory exists
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}
	
	// Write metadata to file
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON:: %w", err)
	}

	if err := os.WriteFile(metadataFilePath, metadataJSON, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}

// generateMetadataDirectory returns the full path to the directory where metadata should be stored
func generateMetadataDirectory(baseFileName string, repoSlug string, vulnID int, packageNum int) string {
	// Convert repo slug to file-safe format
	repoSafeName := strings.ReplaceAll(repoSlug, "/", "-")
	
	// Build the directory path
	relativePath := fmt.Sprintf("data/analysis/cve/%s/%s-%d-%d",
		baseFileName,
		repoSafeName,
		vulnID,
		packageNum)
	
	// Return as relative path
	return "./" + relativePath
}