package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	docker "github.com/ASSERT-KTH/go-cryptoapi/internal/docker"
)

func Usage() {
	fmt.Println("Usage: vulnrun generate -file <vulnerability_json_file> [-up]")
}

func main() {
	composeCmd := flag.NewFlagSet("generate", flag.ExitOnError)
	composeFile := composeCmd.String("file", "", "Path to vulnerability JSON file")
	upFlag := composeCmd.Bool("up", false, "Run docker compose up after generating the compose file")

	if len(os.Args) < 2 {
		Usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		composeCmd.Parse(os.Args[2:])
		if *composeFile == "" {
			fmt.Println("Error: Missing required file path")
			composeCmd.PrintDefaults()
			os.Exit(1)
		}

		outputFile := filepath.Join("internal", "docker", "compose.yaml")
		if err := docker.GenerateCompose(*composeFile, outputFile); err != nil {
			fmt.Printf("Error generating compose file from %s:\n  %v\n", *composeFile, err)
			os.Exit(1)
		}

		if *upFlag {
			// Change to docker directory
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

	default:
		fmt.Printf("Error: Unknown command %q\n", os.Args[1])
		Usage()
		os.Exit(1)
	}
}
