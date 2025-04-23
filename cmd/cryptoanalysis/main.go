package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/flags"
)

// run executes the cryptoanalysis workflow and returns an error on failure.
func run() error {
	// Parse CLI flags and get input dataset path
	cfg, err := flags.ParseFlags()
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
	outDir := filepath.Join("data", "analysis", ds.ID())

	composer := compose.NewComposer(ds, outDir, cfg.Parallelism)

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

	// Cleanup function
	defer func() {	
		if err := compose.StopCompose(composeFilePath); err != nil {
			fmt.Printf("Warning: cleanup failed: %v\n", err)
		}
	}()

	// Run Docker Compose
	if err := composer.RunCompose(composeFilePath); err != nil {
		return fmt.Errorf("failed to run Docker Compose: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
