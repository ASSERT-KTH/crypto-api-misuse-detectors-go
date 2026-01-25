package compose

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/tool"
)

// Composer interface defines methods for generating Docker Compose configurations
type Composer interface {
	// ComposeStr returns the complete Docker Compose YAML content as a string
	// including all services and volume configurations
	ComposeStr() string
	// GetConfig returns the composer's configuration
	GetConfig() ComposerConfig
}

// ComposerConfig contains common configuration for all composers
type ComposerConfig struct {
	// ResultsDir is the directory where analysis results are stored
	ResultsDir string
	// Analysis tools to use
	Tools []tool.Tool
	// Memory configuration for containers
	Memory struct {
		// Limit is the maximum memory a container can use (e.g., "9G")
		Limit string
		// SwapLimit is the maximum memory+swap a container can use (e.g., "9G")
		SwapLimit string
	}
}

// NewComposer creates a new Composer based on the dataset type
func NewComposer(ds dataset.Dataset, cc ComposerConfig) Composer {
	if ds == nil {
		panic("dataset cannot be nil")
	}

	if len(cc.Tools) == 0 {
		panic("at least one tool must be specified")
	}

	if cc.ResultsDir == "" {
		panic("results directory cannot be empty")
	}

	// Set default memory limits if not specified
	if cc.Memory.Limit == "" {
		cc.Memory.Limit = "9G"
	}
	if cc.Memory.SwapLimit == "" {
		cc.Memory.SwapLimit = "9G"
	}

	switch d := ds.(type) {
	case *dataset.ModuleDataset:
		return NewModComposer(d, cc)
	default:
		panic("unsupported dataset type")
	}
}

// WriteComposeFile ensures the target directory exists and writes the Docker Compose YAML.
// It returns the full path to the compose file.
func WriteComposeFile(dir, content string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create docker directory: %w", err)
	}
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write compose file: %w", err)
	}
	return path, nil
}
