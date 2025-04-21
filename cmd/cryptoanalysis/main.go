package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/config"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

func main() {
	cfg, datasetFilePath, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\nUsage: %s [vuln|module] [flags] <input-file>\n",
			err, os.Args[0])
		os.Exit(1)
	}

	// Create the dataset
	ds, err := dataset.CreateDataset(datasetFilePath, cfg.DatasetConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to parse dataset: %w", err))
	}

	if cfg.Verbose {
		fmt.Println("Parsed dataset:", ds)
	}

	// Create composer with parallelism configuration
	composerConfig := compose.DefaultComposerConfig()
	composerConfig.Parallelism = cfg.Parallelism
	composer := compose.NewComposer(ds, composerConfig)

	// Get compose configuration string
	composeStr := composer.ComposeStr()

	if cfg.Verbose {
		fmt.Println("Generated Docker Compose configuration:")
		fmt.Println(composeStr)
	}

	// Create docker directory if it doesn't exist
	if err := os.MkdirAll(cfg.DockerDir, 0755); err != nil {
		log.Fatal(fmt.Errorf("failed to create docker directory: %w", err))
	}

	// Write compose file
	composeFilePath := filepath.Join(cfg.DockerDir, "compose.yaml")
	if err := os.WriteFile(composeFilePath, []byte(composeStr), 0644); err != nil {
		log.Fatal(fmt.Errorf("failed to write compose file: %w", err))
	}
	fmt.Printf("Docker Compose file written to %s\n", composeFilePath)

	// Run Docker Compose with parallelism
	if err := composer.RunCompose(composeFilePath, cfg.Timeout); err != nil {
		log.Fatal(fmt.Errorf("failed to run Docker Compose: %w", err))
	}
}
