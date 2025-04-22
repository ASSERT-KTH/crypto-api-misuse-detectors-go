package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
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

// MetadataWriter handles writing vulnerability metadata to files
type MetadataWriter struct {
	baseDir string
}

// NewMetadataWriter creates a new MetadataWriter with the given base directory
func NewMetadataWriter(baseDir string) *MetadataWriter {
	return &MetadataWriter{
		baseDir: baseDir,
	}
}

// WriteMetadata writes metadata for a vulnerability package to a file
func (mw *MetadataWriter) WriteMetadata(vuln dataset.Vulnerability, pkg dataset.VulPackage, serviceName string) error {
	metadata := VulnerabilityMetadata{
		ID:          vuln.ID,
		Package:     pkg.Name,
		GoVersion:   pkg.GoVersion,
		VulName:     pkg.VulName,
		References:  vuln.References,
		Publish:     pkg.Publish,
		CWE:         vuln.CWE,
		CVE:         vuln.CVE,
		Summary:     pkg.Summary,
		Level:       pkg.Level,
		Score:       pkg.Score,
		Remediation: pkg.Remediation,
		VulRange:    pkg.VulRange,
		VulGitTags:  pkg.VulnerableGitTags,
	}

	// Generate paths using service name
	metadataDir := filepath.Join(mw.baseDir, serviceName)
	metadataFile := filepath.Join(metadataDir, "vulnerability_info.json")

	// Create directory
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	// Write metadata
	jsonData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON: %w", err)
	}

	if err := os.WriteFile(metadataFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}
