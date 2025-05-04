package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/flags"
)

func run() error {

	// tools := []string{"gopher", "gosec", "codeql"}
	// gopher := sast.Tool{}
	// tools := []sast.Tool{sast.Tool{}}

	cfg, err := flags.ParseFlags()
	if err != nil {
		return err
	}

	ds, err := dataset.CreateDataset(cfg.DatasetPath, cfg.DatasetConfig)
	if err != nil {
		return fmt.Errorf("failed to parse dataset: %w", err)
	}
	if cfg.Verbose {
		fmt.Println("Parsed dataset:", ds)
	}

	// Initialize composer
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = filepath.Join("results", ds.ID())
	}

	// Generate Docker Compose configuration file
	composer := compose.NewComposer(ds, cfg.ResultsDir, cfg.Parallelism)
	composeStr := composer.ComposeStr()

	// Write compose file
	composeFilePath, err := compose.WriteComposeFile(cfg.DockerDir, composeStr)
	if err != nil {
		return err
	}

	if cfg.Verbose {
		fmt.Printf("Docker Compose file written to %s\n", composeFilePath)
	}

	// defer cleanup
	defer func() {
		if err := composer.StopCompose(composeFilePath); err != nil {
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
