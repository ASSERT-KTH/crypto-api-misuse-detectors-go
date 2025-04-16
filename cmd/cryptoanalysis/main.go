package main

import (
	"fmt"
	"log"
	"os"

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
	//verbose := true // todo
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

	fmt.Println("Parsed dataset:", ds)

	// //
	// composer, err := compose.NewComposer(ds)
	// if err != nil {
	// 	log.Fatal(fmt.Errorf("failed to create composer: %w", err))
	// }

	// // Get compose configuration string
	// composeStr := composer.ComposeStr()

	// if verbose {
	// 	fmt.Println("Generated Docker Compose configuration:")
	// 	fmt.Println(composeStr)
	// }

	// // Create docker directory if it doesn't exist

	// dockerDir := filepath.Join("internal", "docker")
	// if err := os.MkdirAll(dockerDir, 0755); err != nil {
	// 	log.Fatal(fmt.Errorf("failed to create docker directory: %w", err))
	// }

	// composeFilePath := filepath.Join(dockerDir, "compose.yaml")
	// // Write compose file
	// if err := os.WriteFile(composeFilePath, []byte(composeStr), 0644); err != nil {
	// 	log.Fatal(fmt.Errorf("failed to write compose file: %w", err))
	// }
	// fmt.Printf("Docker Compose file written to %s\n", composeFilePath)

	// // Run docker compose up command with timeout
	// ctx, cancel := context.WithTimeout(context.Background(), 120*time.Minute)
	// defer cancel()

	// cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFilePath, "up", "--build", "--remove-orphans")
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	// if err := cmd.Run(); err != nil {
	// 	log.Fatal(fmt.Errorf("failed to run docker compose up: %w", err))
	// }
}
