package analyzer

import (
	"fmt"
)

type VulPackage struct {
	Name                   string `json:"name"`
	Publish                string `json:"publish"`
	VulName                string `json:"vul_name"`
	VulRange               string `json:"vul_range"`
	Level                  string `json:"level"`
	Score                  string `json:"score"`
	RemediationDescription string `json:"remediation_description"`
	Summary                string `json:"summary"`
	VulGitTags             []struct {
		FullVersion string `json:"full_version"`
	} `json:"vul_git_tags"`
}

type Vulnerability struct {
	ID          int          `json:"id"`
	Repo        Repo         `json:"repo"`
	References  []string     `json:"references"`
	CVE         string       `json:"cve"`
	CWE         string       `json:"cwe"`
	VulPackages []VulPackage `json:"vul_packages"`
}

func (r Repo) String() string {
	return fmt.Sprintf("\n\t\tRepoSlug: %s\n\t\tRepoPath: %s", r.RepoSlug, r.RepoPath)
}

func (p VulPackage) String() string {
	return fmt.Sprintf("\n\t\tName: %s\n\t\tPublish: %s\n\t\tVulName: %s\n\t\tVulRange: %s\n\t\tLevel: %s\n\t\tScore: %s\n\t\tRemediationDescription: %s\n\t\tSummary: %s", p.Name, p.Publish, p.VulName, p.VulRange, p.Level, p.Score, p.RemediationDescription, p.Summary)
}

func (v Vulnerability) String() string {
	return fmt.Sprintf("Vulnerability:\n\tID: %d\n\tCVE: %s\n\tCWE: %s\n\tRepo: %s\n\tVulPackages: %v", v.ID, v.CVE, v.CWE, v.Repo, v.VulPackages)
}
