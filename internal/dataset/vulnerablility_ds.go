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
	// TODO here we should set the service path to ensure it is the same
}

// VulnerabilityConfig holds configuration options specific to vulnerability datasets
type VulnerabilityConfig struct {
	// Filter by severity level (e.g., "high", "medium", "low")
	SeverityLevel string
	// Filter by CWE type
	CWE string
	// Filter by CVE
	CVE string
}

// VulnerabilityDataset implements Dataset for a collection of vulnerabilities
type VulnerabilityDataset struct {
	Vulnerabilities []Vulnerability
}

// Count returns the number of vulnerabilities in the dataset
func (vd VulnerabilityDataset) Count() int {
	totalPackages := 0
	for _, vul := range vd.Vulnerabilities {
		for _, pkg := range vul.VulPackages {
			if pkg.GitTag != "" { // Only count packages with git tags
				totalPackages++
			}
		}
	}
	return totalPackages
}

// Type returns the type of the dataset
func (vd VulnerabilityDataset) Type() DatasetType {
	return VulnerabilityDatasetType
}

// String returns a string representation of the normal module
func (vd VulnerabilityDataset) String() string {
	if len(vd.Vulnerabilities) == 0 {
		return "VulnerabilityDataset{Count: 0}"
	}

	// Take up to 3 samples to show
	sampleSize := 3
	if len(vd.Vulnerabilities) < sampleSize {
		sampleSize = len(vd.Vulnerabilities)
	}

	samples := ""
	for i := 0; i < sampleSize; i++ {
		vuln := vd.Vulnerabilities[i]
		samples += fmt.Sprintf("\n  Package: %s (CVE: %s, Name: %s)",
			vuln.VulPackages[0].Name,
			vuln.CVE,
			vuln.VulPackages[0].VulName)
	}
	samples += "\n  ...\n"

	return fmt.Sprintf("VulnerabilityDataset{Count: %d, ID: %s, Samples:%s}",
		len(vd.Vulnerabilities),
		vd.ID(),
		samples)
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
func ParseVulnerabilities(filepath string, config *VulnerabilityConfig) (*VulnerabilityDataset, error) {
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

	// Apply filters based on configuration
	if config != nil {
		vulnerabilities = filterVulnerabilities(vulnerabilities, config)
	}

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

// filterVulnerabilities applies all configured filters to the vulnerabilities
func filterVulnerabilities(vulnerabilities []Vulnerability, config *VulnerabilityConfig) []Vulnerability {
	return filterVulnerabilitiesByConfig(vulnerabilities, func(v Vulnerability) bool {
		// Filter by severity level if specified
		if config.SeverityLevel != "" {
			for _, pkg := range v.VulPackages {
				if pkg.Level != config.SeverityLevel {
					return false
				}
			}
		}

		// Filter by CWE if specified
		if config.CWE != "" && v.CWE != config.CWE {
			return false
		}

		// Filter by CVE if specified
		if config.CVE != "" && v.CVE != config.CVE {
			return false
		}

		return true
	})
}

// filterVulnerabilitiesByConfig applies a filter function to the vulnerabilities
func filterVulnerabilitiesByConfig(vulnerabilities []Vulnerability, filterFunc func(Vulnerability) bool) []Vulnerability {
	var filtered []Vulnerability
	for _, v := range vulnerabilities {
		if filterFunc(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
