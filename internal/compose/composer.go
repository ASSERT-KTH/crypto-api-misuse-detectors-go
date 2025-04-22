package compose

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// Composer interface defines methods for generating Docker Compose configurations
type Composer interface {
	// ComposeStr returns the complete Docker Compose YAML content as a string
	// including all services and volume configurations
	ComposeStr() string
	// RunCompose executes the Docker Compose configuration
	RunCompose(composeFilePath string) error
	// TODO add "up"
}

// NewComposer creates a new Composer based on the dataset type
func NewComposer(ds dataset.Dataset, outDir string, parallelism int) Composer {
	if ds == nil {
		panic("dataset cannot be nil")
	}
	// Apply default output directory if not set
	if outDir == "" {
		outDir = "data/analysis"
	}
	// Apply default parallelism if non-positive
	if parallelism <= 0 {
		parallelism = 4
	}

	outDir = filepath.Join(outDir, ds.ID())

	switch v := ds.(type) {
	case *dataset.VulnerabilityDataset:
		return NewVulComposer(v, outDir, parallelism)
	case *dataset.ModuleDataset:
		return NewModComposer(v, outDir, parallelism)
	default:
		panic("unsupported dataset type")
	}
}

// RunCompose executes docker compose with the given file path and parallelism level
func RunCompose(composeFilePath string, parallelism int) error {
	// TODO Check if the compose file and env file and dockerfile exists

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

// func createEnvFile(envPath string) error {
// 	// if no .env file in the directory, create one
// 	envPath := filepath.Join(dir, ".env")
// 	if _, err := os.Stat(envPath); os.IsNotExist(err) {
// 		// Also write a .env file so ${BASE_DIR} is set for variable substitution
// 		cwd, err := os.Getwd()
// 		if err != nil {
// 			return "", fmt.Errorf("failed to get working directory for BASE_DIR: %w", err)
// 		}
// 		envContent := fmt.Sprintf("BASE_DIR=%s\n", cwd)
// 		envPath := filepath.Join(dir, ".env")
// 		if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
// 			return "", fmt.Errorf("failed to write .env file: %w", err)
// 		}
// 	}
// }
