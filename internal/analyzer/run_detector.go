package analyzer

/* run gopher tool on the collected packages  */

type GopherConfig struct {
	ToolPath         string
	Timeout          int
	IncludeTestFiles bool
}

func RunGopherTool(module Repo, config GopherConfig) {
	// Execute gopher tool on collected repositories
}

// TODO continue here.
