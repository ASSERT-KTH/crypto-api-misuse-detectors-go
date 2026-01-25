package dataset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"

)

// TODO needs refactoring

// writeJSON is a helper that marshals data to JSON and writes it to a file under baseDir/serviceName
func (mw *MetadataWriter) writeJSON(serviceName, fileName string, data interface{}) error {
	metadataDir := filepath.Join(mw.baseDir, serviceName)
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory %s: %w", metadataDir, err)
	}
	filePath := filepath.Join(metadataDir, fileName)

	// Create a custom encoder with HTML escaping disabled
	buf := new(bytes.Buffer)
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false) // Disable HTML escaping
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON: %w", err)
	}

	// Remove the trailing newline that encoder.Encode adds
	jsonData := bytes.TrimSpace(buf.Bytes())

	// Write the encoded data to file
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
func (mw *MetadataWriter) WriteModuleMetadata(mod Module, serviceName string) error {
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

// escapeStrings escapes HTML special characters in a slice of strings
func escapeStrings(strs []string) []string {
	escaped := make([]string, len(strs))
	for i, s := range strs {
		escaped[i] = html.EscapeString(s)
	}
	return escaped
}
