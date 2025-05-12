package sast

import (
	"fmt"
)

const (
	codeqlMountTo     = "/analysis/codeql-home"
	codeqlSuiteFile   = "/analysis/codeql-home/codeql/qlpacks/codeql/go-queries/1.1.13/codeql-suites/crypto-cwes.qls"
	codeqlResultsPath = "/analysis/results/"
)

type codeqlTool struct{}

// Name returns the name of the CodeQL tool
func (t *codeqlTool) Name() string {
	return "codeql"
}

// GetDockerConfig returns the Docker configuration for running CodeQL analysis
func (t *codeqlTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeName:      "codeql",
		VolumeTopLevel:  fmt.Sprintf("%s/codeql-home", Toolspath),
		VolumeAttribute: fmt.Sprintf("codeql:%s", codeqlMountTo),
		Command:         []string{"/bin/sh", "-c", fmt.Sprintf("%s/run_codeql_analysis.sh", codeqlMountTo)},
		ResultsDir:      codeqlResultsPath,
	}
}

// CodeQLTool is the default instance of the CodeQL tool
var CodeQLTool Tool = &codeqlTool{}
