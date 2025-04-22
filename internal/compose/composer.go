package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ComposerConfig holds configuration for the composer
type ComposerConfig struct {
	OutDir      string
	Parallelism int
}

// DefaultComposerConfig returns a default composer configuration
func DefaultComposerConfig() *ComposerConfig {
	return &ComposerConfig{
		OutDir:      "data/analysis",
		Parallelism: 4,
	}
}

// Composer interface defines methods for generating Docker Compose configurations
type Composer interface {
	// ComposeStr returns the complete Docker Compose YAML content as a string
	// including all services and volume configurations
	ComposeStr() string
	// RunCompose executes the Docker Compose configuration
	RunCompose(composeFilePath string, timeout time.Duration) error
	// TODO add "up"
}

// NewComposer creates a new Composer based on the dataset type
func NewComposer(ds dataset.Dataset, outdir string, parallelism int) Composer {
	if outdir == "" {
		outdir = ""
	}
	if parallelism <= 0 {
		parallelism = 4
	}

	config := &ComposerConfig{
		OutDir:      outdir,
		Parallelism: parallelism,
	}

	switch v := ds.(type) {
	case *dataset.VulnerabilityDataset:
		return NewVulComposer(v, config)
	case *dataset.ModuleDataset:
		return NewModComposer(v, config)
	default:
		panic("unsupported dataset type")
	}
}

// RunCompose executes docker compose with the given file path and parallelism level
func RunCompose(composeFilePath string, parallelism int, timeout time.Duration) error {
	// Build the docker compose command with parallelism
	cmd := exec.Command("docker", "compose", "--parallel", fmt.Sprintf("%d", parallelism), "-f", composeFilePath, "up", "--build")

	// Set timeout for the command
	if timeout > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_CLIENT_TIMEOUT=%d", int(timeout.Seconds())))
	}

	// Run the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

// StopCompose stops all services in the compose file
func StopCompose(composeFilePath string) error {
	cmd := exec.Command("docker", "compose", "-f", composeFilePath, "down")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop docker compose: %v\nOutput: %s", err, string(output))
	}
	return nil
}

// writeComposeFile ensures the target directory exists and writes the Docker Compose YAML.
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
