package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type VulPackage struct {
	Name        string   `json:"name"`
	Publish     string   `json:"publish"`
	VulName     string   `json:"vul_name"`
	VulRange    string   `json:"vul_range"`
	Level       string   `json:"level"`
	Score       string   `json:"score"`
	Remediation string   `json:"remediation_description"`
	Summary     string   `json:"summary"`
	VulGitTags  []string `json:"vul_git_tags"`
	GoVersion   string   `json:"go_version"`
}

type Repo struct {
	RepoSlug string   `json:"repo_slug"`
	GitTags  []string `json:"git_tags"`
}

type Vulnerability struct {
	ID          int          `json:"id"`
	Repo        Repo         `json:"repo"`
	References  []string     `json:"references"`
	CVE         string       `json:"cve"`
	CWE         string       `json:"cwe"`
	VulPackages []VulPackage `json:"vul_packages"`
}

// readVulnerabilities reads and parses the vulnerabilities from JSON file
func readVulnerabilities(filepath string) ([]Vulnerability, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var vulnerabilities []Vulnerability
	if err := json.Unmarshal(data, &vulnerabilities); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return vulnerabilities, nil
}
