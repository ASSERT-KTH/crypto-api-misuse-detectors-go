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
	URL      string
}

type VulPackage struct {
	Name              string   `json:"name"`
	Publish           string   `json:"publish"`
	VulName           string   `json:"vul_name"`
	VulRange          string   `json:"vul_range"`
	Level             string   `json:"level"`
	Score             string   `json:"score"`
	Remediation       string   `json:"remediation_description"`
	Summary           string   `json:"summary"`
	VulnerableGitTags []string `json:"vul_git_tags"`
	Commit            string   // TODO...
	GitTag            string   // This is the last in VulnerableGitTags
	GoVersion         string   `json:"go_version"`
}

// VulnerabilityDataset implements Dataset for a collection of vulnerabilities
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

// ID returns a string identifier for the dataset
func (vd VulnerabilityDataset) ID() string {
	return fmt.Sprintf("%s-%d", vd.Type(), vd.Count())
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

	vulnerabilities = setGitTag(vulnerabilities)
	vulnerabilities = setURL(vulnerabilities)

	return &VulnerabilityDataset{
		Vulnerabilities: vulnerabilities,
	}, nil
}

// setGitTag sets the GitTag field for each vulnerable package
// using the most recent tag from its VulGitTags and returns the modified vulnerabilities
func setGitTag(vulnerabilities []Vulnerability) []Vulnerability {
	for i := range vulnerabilities {
		for j := range vulnerabilities[i].VulPackages {
			vulPackage := &vulnerabilities[i].VulPackages[j]

			if tags := vulPackage.VulnerableGitTags; len(tags) > 0 {
				vulPackage.GitTag = tags[len(tags)-1] // Use the last tag
			} else {
				vulPackage.GitTag = "" // No tags available
			}
		}
	}
	return vulnerabilities
}


func setURL(vulnerabilities []Vulnerability) []Vulnerability {
	for i := range vulnerabilities {
		vulnerabilities[i].Repo.URL = fmt.Sprintf("https://%s", vulnerabilities[i].Repo.RepoSlug)
	}
	return vulnerabilities
}