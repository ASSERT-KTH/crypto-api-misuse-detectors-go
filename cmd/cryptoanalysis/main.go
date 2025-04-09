package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

func Usage() {
	fmt.Println("Usage: ./cryptoanalysis <input_file>")
	fmt.Println("\tParses data in given file based on its extension:")
	fmt.Println("\t  .json - Vulnerability specification")
	fmt.Println("\t  .csv  - Go modules specification")
	fmt.Println("\tGenerates docker-compose file and analyses them by running `docker compose up`")
}

func main() {
	if len(os.Args) != 2 {
		Usage()
		os.Exit(1)
	}

	inputPath := os.Args[1]
	if inputPath == "" {
		fmt.Println("Error: Input file path is required")
		Usage()
		os.Exit(1)
	}

	// Parse the ds based on file extension
	ds, err := dataset.ParseDataset(inputPath)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to parse dataset: %w", err))
	}

	//
	composer, err := compose.CreateComposer(ds)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create composer: %w", err))
	}

	// TODO this variable use and name is not clear
	outputBasePath := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	composeStr := composer.GenerateComposeStr(outputBasePath)
	fmt.Println(composeStr)


	// Write compose file
	if err := os.WriteFile(filepath.Join("internal", "docker", "compose.yaml"), []byte(composeStr), 0644); err != nil {
		log.Fatal(fmt.Errorf("failed to write compose file: %w", err))
	}

	// // Run docker compose up command
	// if err := os.Chdir("internal/docker"); err != nil {
	// 	fmt.Printf("Error changing to docker directory: %v\n", err)
	// 	os.Exit(1)
	// }
	// dockerComposeCmd := exec.Command("docker", "compose", "up", "--build", "--remove-orphans")
	// dockerComposeCmd.Stdout = os.Stdout
	// dockerComposeCmd.Stderr = os.Stderr

	// if err := dockerComposeCmd.Run(); err != nil {
	// 	fmt.Printf("Error running docker compose: %v\n", err)
	// 	os.Exit(1)
	// }
}
