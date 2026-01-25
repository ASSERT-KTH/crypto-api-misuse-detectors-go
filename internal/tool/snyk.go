package tool

import "fmt"

type snykTool struct{}

func (snykTool) Name() string {
	return "snyk"
}

func (snykTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeTopLevel:  fmt.Sprintf("%s/snyk", Toolspath),
		VolumeAttribute: "snyk:/analysis/snyk",
		Command:         []string{"/bin/sh", "-c", "/analysis/snyk/run_snyk.sh"},
		Environment:     []string{"SNYK_TOKEN=${SNYK_TOKEN}"},
	}
}

// String returns a string representation of the DockerConfig
func (sn snykTool) String() string {
	return fmt.Sprintf("%s: %s", sn.Name(), sn.GetDockerConfig().String())
}

var SnykTool Tool = snykTool{}
