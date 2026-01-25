package flags

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/tool"
)

// Config holds the command line configuration
type Config struct {
	DatasetPath string
	ResultsDir  string
	Verbose     bool
	DockerDir   string
	Tools       []tool.Tool
}

// ParseFlags parses command line flags and returns a Config
func ParseFlags() (*Config, error) {
	// Define flags
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	dockerDir := flag.String("docker-dir", "internal/docker", "Directory for Docker files")
	analysisOutDir := flag.String("out-dir", "results", "Directory for storing analysis results")
	toolsStr := flag.String("tools", "", "Comma-separated list of tools to use (gopher,codeql,gosec,snyk)")

	// Parse flags
	flag.Parse()

	// Parse tools flag
	toolMap := map[string]tool.Tool{
		"gopher": tool.GopherTool,
		"codeql": tool.CodeQLTool,
		"gosec":  tool.GoSecTool,
		"snyk":   tool.SnykTool,
	}

	if *toolsStr == "" {
		return nil, fmt.Errorf("no tools specified. Use -tools flag to specify which tools to use (gopher,codeql,gosec,snyk)")
	}

	tools := parseToolsFlag(*toolsStr, toolMap)
	if len(tools) == 0 {
		return nil, fmt.Errorf("no valid tools specified. Available tools: gopher,codeql,gosec,snyk")
	}

	// Get dataset path from positional argument
	args := flag.Args()
	if len(args) != 1 {
		return nil, fmt.Errorf("dataset path is required as a positional argument")
	}

	datasetPath := args[0]
	if _, err := os.Stat(datasetPath); err != nil {
		return nil, fmt.Errorf("dataset path '%s' does not exist", datasetPath)
	}

	config := &Config{
		DatasetPath: datasetPath,
		ResultsDir:  *analysisOutDir,
		Verbose:     *verbose,
		Tools:       tools,
		DockerDir:   *dockerDir,
	}

	return config, nil
}

// parseToolsFlag parses the tools flag string into a slice of tools
func parseToolsFlag(toolsStr string, toolMap map[string]tool.Tool) []tool.Tool {
	var tools []tool.Tool
	for _, t := range strings.Split(toolsStr, ",") {
		t = strings.TrimSpace(t)
		if tool, ok := toolMap[t]; ok {
			tools = append(tools, tool)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Unknown tool '%s'. Available tools: gopher,codeql,gosec,snyk\n", t)
		}
	}
	return tools
}
