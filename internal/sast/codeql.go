package sast

import (
	"fmt"
	"strings"
)

const (
	codeqlMountTo     = "/analysis/codeql-home"
	codeqlResultsDir  = "/analysis/db/results/codeql/go-queries/Security"
	codeqlSuiteFile   = "/analysis/codeql-home/codeql/qlpacks/codeql/go-queries/1.1.13/codeql-suites/crypto-cwes.qls"
	codeqlResultsFile = "crypto-cwes-result.csv"
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
		Command:         buildCodeQLCommand(),
		ResultsDir:      codeqlResultsDir,
	}
}

// buildCodeQLCommand constructs the command string for running CodeQL analysis
func buildCodeQLCommand() string {
	var builder strings.Builder
	builder.WriteString(buildDatabaseCreateCmd())
	builder.WriteString(" && ")
	builder.WriteString(buildDatabaseAnalyzeCmd())
	return builder.String()
}

// buildDatabaseCreateCmd builds the command for creating a CodeQL database
func buildDatabaseCreateCmd() string {
	return fmt.Sprintf(
		"%s/codeql/codeql database create --language=go --source-root=%s %s/db",
		codeqlMountTo, RepoPathDocker, codeqlResultsDir)
}

// buildDatabaseAnalyzeCmd builds the command for analyzing a CodeQL database
func buildDatabaseAnalyzeCmd() string {
	return fmt.Sprintf(
		"%s/codeql/codeql database analyze /analysis/db %s --format=csv --output=%s/%s",
		codeqlMountTo, codeqlSuiteFile, codeqlResultsDir, codeqlResultsFile)
}

// CodeQLTool is the default instance of the CodeQL tool
var CodeQLTool Tool = &codeqlTool{}
