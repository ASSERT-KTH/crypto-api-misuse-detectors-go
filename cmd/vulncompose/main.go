package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
)

func Usage() {
	fmt.Println("Usage: ./vulncompose <vulnerability_json_file>")
	fmt.Println("  Generates docker-compose file from vulnerability spec and analyses them by running `docker compose up`")
}

func main() {
	if len(os.Args) != 2 {
		Usage()
		os.Exit(1)
	}

	vulnerabilityFilePath := os.Args[1]
	if vulnerabilityFilePath == "" {
		fmt.Println("Error: Vulnerability JSON file path is required")
		Usage()
		os.Exit(1)
	}
	if !strings.HasSuffix(vulnerabilityFilePath, ".json") {
		fmt.Println("Error: Invalid file type. Please provide a JSON file.")
		Usage()
		os.Exit(1)
	}

	composeFilePath := filepath.Join("internal", "docker", "compose.yaml")
	if err := compose.GenerateCompose(vulnerabilityFilePath, composeFilePath); err != nil {
		fmt.Printf("Error generating compose file from %s:\n  %v\n", vulnerabilityFilePath, err)
		os.Exit(1)
	}

	if err := os.Chdir("internal/docker"); err != nil {
		fmt.Printf("Error changing to docker directory: %v\n", err)
		os.Exit(1)
	}

	// Run docker compose command
	dockerComposeCmd := exec.Command("docker", "compose", "up", "--build", "--remove-orphans")
	dockerComposeCmd.Stdout = os.Stdout
	dockerComposeCmd.Stderr = os.Stderr

	if err := dockerComposeCmd.Run(); err != nil {
		fmt.Printf("Error running docker compose: %v\n", err)
		os.Exit(1)
	}

}
