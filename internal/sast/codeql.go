package sast

import (
	"fmt"
	"strings"
)

const (
	// Paths for CodeQL tool configuration
	mountTo    = "/analysis/codeql-home"
	resultsDir = "/analysis/codeql-results"
	//queryPath = "/analysis/codeql-home/codeql-repo/go/ql/src/Security"

	// Default output file for CodeQL results
	resultsFilename = "results.csv"

	// Output formats
	formatCSV = "csv"
	//formatSARIF = "sarif-latest"

	// Query suite file
	querySuiteFile = "/analysis/codeql-home/cwe-suite.qls"
)

// DefaultCWEs represents the default list of Common Weakness Enumerations to check for
// var DefaultCWEs = []string{
// 	"CWE-338", // Weak Cryptography
// 	"CWE-798", // Use of Hard-coded Credentials
// 	"CWE-326", // Inadequate Encryption Strength
// 	"CWE-327", // Use of a Broken or Risky Cryptographic Algorithm
// 	"CWE-332", // Insufficient Entropy in PRNG
// 	"CWE-347", // Improper Verification of Cryptographic Signature
// }

// codeqlTool implements the Tool interface for CodeQL analysis
type codeqlTool struct{}

// Name returns the name of the CodeQL tool
func (t *codeqlTool) Name() string {
	return "codeql"
}

// GetDockerConfig returns the Docker configuration for running CodeQL analysis
func (t *codeqlTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeName:      "codeql",
		VolumeTopLevel:  "${BASE_DIR}/codeql-home",
		VolumeAttribute: fmt.Sprintf("codeql:%s", mountTo),
		Command:         buildCodeQLCommand(),
		OutputDir:       resultsDir,
	}
}

// buildCodeQLCommand constructs the command string for running CodeQL analysis
func buildCodeQLCommand() string {
	var builder strings.Builder

	// Build database creation command
	builder.WriteString(buildDatabaseCreateCmd())
	builder.WriteString(" && ")
	builder.WriteString(buildDatabaseAnalyzeCmd())

	return builder.String()
}

// buildDatabaseCreateCmd builds the command for creating a CodeQL database
func buildDatabaseCreateCmd() string {
	return fmt.Sprintf("%s/codeql/codeql database create --language=go --source-root=%s %s/db",
		mountTo, repoPathDocker, resultsDir)
}

// buildDatabaseAnalyzeCmd builds the command for analyzing a CodeQL database
func buildDatabaseAnalyzeCmd() string {
	return fmt.Sprintf("%s/codeql/codeql database analyze %s/db %s --format=%s, --output=%s/%s",
		mountTo, resultsDir, querySuiteFile, formatCSV, resultsDir, resultsFilename)
}

// DefaultCodeQLTool is a constant that implements the Tool interface for CodeQL analysis
var CodeQLTool Tool = &codeqlTool{}
