package sast

import (
	"fmt"
	"strings"
)

// CodeQLTool is a constant that implements the Tool interface
var CodeQLTool Tool = codeqlTool{}

type codeqlTool struct{}

// DefaultOutputFile is the default output file for CodeQL results
var DefaultOutputFile = "results.sarif"

// DefaultQueries is the default set of CWE queries to run
var DefaultQueries = []string{
	"security-and-quality/go/security-extended.qls",
	"security-and-quality/go/security-crypto.qls",
	"security-and-quality/go/security-crypto-weak-random.qls",
	"security-and-quality/go/security-crypto-bad-ciphers.qls",
	"security-and-quality/go/security-crypto-bad-hash.qls",
}

func (codeqlTool) Name() string {
	return "codeql"
}

func (codeqlTool) GetDockerConfig() DockerConfig {
	// Join queries with commas for the command
	queries := strings.Join(DefaultQueries, ",")

	return DockerConfig{
		Volumes:   "codeql:/analysis/codeql",
		Command:   fmt.Sprintf("codeql database create --language=go --source-root=/analysis/repo /analysis/codeql/db && codeql database analyze /analysis/codeql/db --query-spec=%s --format=sarif-latest --output=/analysis/repo/scan_results/%s", queries, DefaultOutputFile),
		OutputDir: "/analysis/repo/scan_results",
	}
}

// GetCWEs returns the list of CWE queries to run
func (codeqlTool) GetCWEs() []string {
	return DefaultQueries
}
