package main

import (
	"fmt"
	"log"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/config"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// run executes the cryptoanalysis workflow and returns an error on failure.
func run() error {
	// Parse CLI flags and get input dataset path
	cfg, err := config.ParseFlags()
	if err != nil {
		return err
	}

	// TODO a verify function to check if the dataset path is valid

	// Create the dataset
	ds, err := dataset.CreateDataset(cfg.DatasetPath, cfg.DatasetConfig)
	if err != nil {
		return fmt.Errorf("failed to parse dataset: %w", err)
	}
	if cfg.Verbose {
		fmt.Println("Parsed dataset:", ds)
	}

	// Initialize composer
	composer := compose.NewComposer(ds, "data/analysis", cfg.Parallelism)

	// Generate Docker Compose configuration
	composeStr := composer.ComposeStr()
	if cfg.Verbose {
		fmt.Println("Generated Docker Compose configuration:")
		fmt.Println(composeStr)
	}

	// Write compose file
	composeFilePath, err := compose.WriteComposeFile(cfg.DockerDir, composeStr)
	if err != nil {
		return err
	}

	if cfg.Verbose {
		fmt.Printf("Docker Compose file written to %s\n", composeFilePath)
	}
	
	// Run Docker Compose
	if err := composer.RunCompose(composeFilePath, cfg.Timeout); err != nil {
		return fmt.Errorf("failed to run Docker Compose: %w", err)
	}
	return nil
}

// main is the entry point for the tool.
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
