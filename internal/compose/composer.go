package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
)

// Composer interface defines methods for generating Docker Compose configurations
type Composer interface {
	// ComposeStr returns the complete Docker Compose YAML content as a string
	// including all services and volume configurations
	ComposeStr() string
	// RunCompose executes the Docker Compose configuration
	RunCompose(composeFilePath string) error
	// StopCompose stops all services in the compose file
	StopCompose(composeFilePath string) error
	// GetConfig returns the composer's configuration
	GetConfig() Config
}

// Config contains common configuration for all composers
type Config struct {
	// Dataset-specific directory (e.g., vulnerabilities/, starred-repos/)
	DatasetDir string
	// Number of parallel operations
	Parallelism int
	// Analysis tools to use
	Tools []sast.Tool
}

func NewConfig(ds dataset.Dataset, parallelism int, tools []sast.Tool) Config {
	return Config{
		DatasetDir:  time.Now().Format("2006-01-02-15-04"),
		Parallelism: parallelism,
		Tools:       tools,
	}
}

// NewComposer creates a new Composer based on the dataset type
func NewComposer(ds dataset.Dataset, parallelism int, tools []sast.Tool) Composer {
	if ds == nil {
		panic("dataset cannot be nil")
	}

	if len(tools) == 0 {
		panic("at least one tool must be specified")
	}

	// Ensure parallelism is within bounds
	if parallelism < 4 {
		parallelism = 4
	} else if parallelism > 10 {
		parallelism = 10
	}

	// Create config with common configuration
	config := NewConfig(ds, parallelism, tools)

	switch d := ds.(type) {
	case *dataset.VulnerabilityDataset:
		return NewVulComposer(d, config)
	case *dataset.ModuleDataset:
		return NewModComposer(d, config)
	default:
		panic("unsupported dataset type")
	}
}

// RunCompose executes docker compose with the given file path and parallelism level
func RunCompose(composeFilePath string, parallelism int) error {
	// Build the docker compose command with parallelism
	cmd := exec.Command("docker", "compose", "--parallel", fmt.Sprintf("%d", parallelism), "-f", composeFilePath, "up", "--build")
	cmd.Env = append(cmd.Env, "DOCKER_CLIENT_TIMEOUT=60")

	// Stream stdout/stderr so users see logs in real time
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose failed: %v", err)
	}
	return nil
}

// WaitDown stops all services in the compose file
func WaitDown(composeFilePath string) error {
	//cmd := exec.Command("docker", "compose", "-f", composeFilePath, "down", "--remove-orphans")
	cmd := exec.Command("docker", "compose", "-f", composeFilePath, "wait", "--down-project")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop docker compose: %v\nOutput: %s", err, string(output))
	}
	return nil
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

// Helper to get a MetadataWriter for a given config and service name
func getMetadataWriter(cfg Config) *dataset.MetadataWriter {
	// Use the same path configuration as services
	pc := DefaultPaths()
	metadataDir := filepath.Join(pc.ResultsDir, cfg.DatasetDir)
	return dataset.NewMetadataWriter(metadataDir)
}
