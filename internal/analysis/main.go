package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Usage() {
	fmt.Println("Usage: ./analysis <vulnerability_json_file>")
	fmt.Println("  Generates docker-compose file and runs docker compose up")
}

func main() {
	if len(os.Args) != 2 {
		Usage()
		os.Exit(1)
	}

	vulFilepath := os.Args[1]
	if vulFilepath == "" {
		fmt.Println("Error: Vulnerability JSON file path is required")
		Usage()
		os.Exit(1)
	}
	if !strings.HasSuffix(vulFilepath, ".json") {
		fmt.Println("Error: Invalid file type. Please provide a JSON file.")
		Usage()
		os.Exit(1)
	}

	outputFile := filepath.Join("internal", "docker", "compose.yaml")
	if err := GenerateCompose(vulFilepath, outputFile); err != nil {
		fmt.Printf("Error generating compose file from %s:\n  %v\n", vulFilepath, err)
		os.Exit(1)
	}

	if err := os.Chdir("internal/docker"); err != nil {
		fmt.Printf("Error changing to docker directory: %v\n", err)
		os.Exit(1)
	}

	// Run docker compose command
	cmd := exec.Command("docker", "compose", "up", "--build", "--remove-orphans")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running docker compose: %v\n", err)
		os.Exit(1)
	}

}
