package tool

import (
	"fmt"
)

type codeqlTool struct{}

func (t *codeqlTool) Name() string {
	return "codeql"
}

// GetDockerConfig returns the Docker configuration for running CodeQL analysis
func (t *codeqlTool) GetDockerConfig() DockerConfig {
	var codeqlMountTo = "/analysis/codeql-home"
	return DockerConfig{
		VolumeTopLevel:  fmt.Sprintf("%s/codeql-home", Toolspath),
		VolumeAttribute: fmt.Sprintf("codeql:%s", codeqlMountTo),
		Command:         []string{"/bin/sh", "-c", fmt.Sprintf("%s/run_codeql.sh", codeqlMountTo)},
	}
}

// String returns a string representation of the DockerConfig
func (cql codeqlTool) String() string {
	return fmt.Sprintf("%s: %s", cql.Name(), cql.GetDockerConfig().String())
}

var CodeQLTool Tool = &codeqlTool{}
