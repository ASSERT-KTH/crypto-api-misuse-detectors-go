package analyzer

/* run gopher tool on the collected packages  */

import (
	"github.com/ASSERT-KTH/go-cryptoapi/internal/collector"
)

type GopherConfig struct {
	ToolPath         string
	Timeout          int
	IncludeTestFiles bool
}

func RunGopherTool(module collector.Module, config GopherConfig) {
	// Execute gopher tool on collected repositories
}

// TODO continue here.
