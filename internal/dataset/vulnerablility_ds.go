package dataset

import (
	"encoding/json"
	"fmt"
	"os"
)

// Definitions from the JSON vulnerability files
type Vulnerability struct {
	ID          int          `json:"id"`
	Repo        Repository   `json:"repo"`
	References  []string     `json:"references"`
	CVE         string       `json:"cve"`
	CWE         string       `json:"cwe"`
	VulPackages []VulPackage `json:"vul_packages"`
}

type Repository struct {
	RepoSlug string   `json:"repo_slug"`
	GitTags  []string `json:"git_tags"`
}

type VulPackage struct {
	Name        string   `json:"name"`
	Publish     string   `json:"publish"`
	VulName     string   `json:"vul_name"`
	VulRange    string   `json:"vul_range"`
	Level       string   `json:"level"`
	Score       string   `json:"score"`
	Remediation string   `json:"remediation_description"`
	Summary     string   `json:"summary"`
	VulGitTags  []string `json:"vul_git_tags"` // change to one tag
	GoVersion   string   `json:"go_version"`
}

// VulnerabilityDataset implements ProjectDataset for a collection of vulnerabilities
type VulnerabilityDataset struct {
	Vulnerabilities []Vulnerability
}

// Count returns the number of vulnerabilities in the dataset
func (vd VulnerabilityDataset) Count() int {
	return len(vd.Vulnerabilities)
}

// Type returns the type of the dataset
func (vd VulnerabilityDataset) Type() DatasetType {
	return VulnerabilityDatasetType
}

// String returns a string representation of the vulnerability dataset
func (vd VulnerabilityDataset) String() string {
	return fmt.Sprintf("VulnerableModuleDataset{Count: %d}", len(vd.Vulnerabilities))
}

// GetVulnerabilities returns the vulnerabilities in the dataset
func (vd *VulnerabilityDataset) GetVulnerabilities() []Vulnerability {
	return vd.Vulnerabilities
}

// ParseVulnerabilities reads and parses the vulnerabilities from a JSON file
func ParseVulnerabilities(filepath string) (*VulnerabilityDataset, error) {
	// Read the file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulnerable packages file: %w", err)
	}

	// Parse JSON data
	var vulnerabilities []Vulnerability
	if err := json.Unmarshal(data, &vulnerabilities); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability JSON: %w", err)
	}

	return &VulnerabilityDataset{
		Vulnerabilities: vulnerabilities,
	}, nil
}

// GetDatasetIdentifier returns a string identifier for the dataset
func (vd VulnerabilityDataset) GetDatasetIdentifier() string {
	return fmt.Sprintf("%s-%d", vd.Type(), vd.Count())
}
