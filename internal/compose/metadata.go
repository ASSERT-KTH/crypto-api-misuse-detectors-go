package compose

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// TODO needs many refactoring


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

// writeJSON is a helper that marshals data to JSON and writes it to a file under baseDir/serviceName
func (mw *MetadataWriter) writeJSON(serviceName, fileName string, data interface{}) error {
	metadataDir := filepath.Join(mw.baseDir, serviceName)
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory %s: %w", metadataDir, err)
	}
	filePath := filepath.Join(metadataDir, fileName)
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON: %w", err)
	}
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file %s: %w", filePath, err)
	}
	return nil
}

// MetadataWriter handles writing metadata for vulnerability packages and modules to files
type MetadataWriter struct {
	baseDir string
}

// NewMetadataWriter creates a new MetadataWriter with the given base directory
func NewMetadataWriter(baseDir string) *MetadataWriter {
	return &MetadataWriter{
		baseDir: baseDir,
	}
}

// WriteVulMetadata writes metadata for a vulnerability package to a file
func (mw *MetadataWriter) WriteVulMetadata(vuln dataset.Vulnerability, pkg dataset.VulPackage, serviceName string) error {
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
	return mw.writeJSON(serviceName, "vulnerability_info.json", metadata)
}

// ModuleMetadata represents the metadata for a module
type ModuleMetadata struct {
	ID          string `json:"id"`
	RepoName    string `json:"repo_name"`
	URL         string `json:"url"`
	Stars       int    `json:"stars"`
	LOC         int    `json:"loc"`
	Size        int    `json:"size"`
	ForksCount  int    `json:"forks_count"`
	Issues      int    `json:"issues"`
	CreatedAt   string `json:"created_at"`
	Description string `json:"description"`
	Archived    string `json:"archived"`
	Educational string `json:"educational"`
	OutOfDate   string `json:"outofdate"`
	ReleaseTag  string `json:"tag"`
	Commit      string `json:"commit"`
	GoVersion   string `json:"go_version"`
}

// WriteModuleMetadata writes metadata for a module to a file
func (mw *MetadataWriter) WriteModuleMetadata(mod dataset.Module, serviceName string) error {
	metadata := ModuleMetadata{
		ID:          mod.ID,
		RepoName:    mod.RepoName,
		URL:         mod.URL,
		Stars:       mod.Stars,
		LOC:         mod.LOC,
		Size:        mod.Size,
		ForksCount:  mod.ForksCount,
		Issues:      mod.Issues,
		CreatedAt:   mod.CreatedAt,
		Description: mod.Description,
		Archived:    mod.Archived,
		Educational: mod.Educational,
		OutOfDate:   mod.OutOfDate,
		ReleaseTag:  mod.ReleaseTag,
		Commit:      mod.Commit,
		GoVersion:   mod.GoVersion,
	}

	return mw.writeJSON(serviceName, "module_info.json", metadata)
}
