package analyzer

import (
	"fmt"
)

// Represents a package affected by a vulnerability and metadata about how it's affected.
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
	TriedTags int
}

func (p VulPackage) String() string {
	return fmt.Sprintf("VulPackage:\n\tName: %s\n\tPublish: %s\n\tVulName: %s\n\tVulRange: %s\n\tLevel: %s\n\tScore: %s\n\tRemediationDescription: %s\n\tSummary: %s", p.Name, p.Publish, p.VulName, p.VulRange, p.Level, p.Score, p.RemediationDescription, p.Summary)
}

// Peeks if there are any git tags left to pop.
func (p *VulPackage) hasTagsLeft() bool {
	numTags := len(p.VulGitTags)
	return (numTags - p.TriedTags) > 0
}

// Gets the latest vulnerable git tag that has not been tested yet.
func (p *VulPackage) PopVulTag() (string, error) {
	// check if there are any tags left
	if !p.hasTagsLeft() {
		return "", fmt.Errorf("no vulnerable git tags found")
	}
	// get the latest tag based on tried tags
	numTags := len(p.VulGitTags)
	tag := p.VulGitTags[numTags-p.TriedTags-1].FullVersion
	p.TriedTags++
	return tag, nil
}
