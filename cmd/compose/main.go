package main

import (
	"fmt"
	"os"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/flags"
	"github.com/sirupsen/logrus"
)

func run() error {
	config, err := flags.ParseFlags()
	if err != nil {
		return fmt.Errorf("failed to parse flags: %v", err)
	}

	// Set up logging
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	if config.Verbose {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	// Load dataset
	ds, err := dataset.CreateDataset(config.DatasetPath, dataset.ModuleDatasetType)
	if err != nil {
		return fmt.Errorf("failed to load dataset: %v", err)
	}
	fmt.Println(config.ResultsDir)
	// Create results directory
	if err := os.MkdirAll(config.ResultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %v", err)
	}

	// Log tools configuration
	toolNames := make([]string, len(config.Tools))
	for i, t := range config.Tools {
		toolNames[i] = t.Name()
	}
	log.Infof("Configured tools: %v", toolNames)

	// Set up tools from config
	if len(config.Tools) == 0 {
		return fmt.Errorf("no tools specified. Use -tools flag to specify which tools to use")
	}

	// todo this is repetition from flags
	cc := compose.ComposerConfig{
		ResultsDir: config.ResultsDir,
		Tools:      config.Tools,
	}
	composer := compose.NewComposer(ds, cc)
	composeStr := composer.ComposeStr()

	// Write compose file
	composeFilePath, err := compose.WriteComposeFile(config.DockerDir, composeStr)
	if err != nil {
		return fmt.Errorf("failed to write compose file: %v", err)
	}

	if config.Verbose {
		log.Infof("Generation complete. Compose yaml can be found in %s/compose.yaml", composeFilePath)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
