package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/compose"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

var (
	// Module dataset specific flags
	moduleLimit       = flag.Int("module-limit", 550, "Limit the number of modules to include (top N by stars)")
	filterArchived    = flag.Bool("no-archived", true, "Filter out archived repositories")
	filterEducational = flag.Bool("no-educational", true, "Filter out educational repositories")
	filterOutOfDate   = flag.Bool("no-out-of-date", true, "Filter out out-of-date repositories")
	filterIncomplete  = flag.Bool("no-incomplete", true, "Filter out out-of-date repositories")

	// Vulnerability dataset specific flags
	severityLevel = flag.String("severity", "", "Filter vulnerabilities by severity level (e.g., high, medium, low)")
	cwe           = flag.String("cwe", "", "Filter vulnerabilities by CWE type")
	cve           = flag.String("cve", "", "Filter vulnerabilities by CVE")

	// General flags
	verbose = flag.Bool("verbose", true, "Enable verbose output")
)

func Usage() {
	fmt.Println("Usage: ./cryptoanalysis [options] <input_file>")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nInput file types:")
	fmt.Println("  .json - Vulnerability specification")
	fmt.Println("  .csv  - Go modules specification")
	fmt.Println("\nExamples:")
	fmt.Println("  ./cryptoanalysis -module-limit=500 -filter-archived=true modules.csv")
	fmt.Println("  ./cryptoanalysis -severity=high -cwe=CWE-327 vulnerabilities.json")
}

func createDatasetConfig(filepath string) *dataset.DatasetConfig {
	// Create base config from file
	config := dataset.NewDatasetConfigFromFile(filepath)

	// Configure based on dataset type
	switch config.Type {
	case dataset.ModuleDatasetType:
		config.ModuleConfig.Limit = *moduleLimit
		config.ModuleConfig.FilterArchived = *filterArchived
		config.ModuleConfig.FilterEducational = *filterEducational
		config.ModuleConfig.FilterOutOfDate = *filterOutOfDate
		config.ModuleConfig.FilterIncomplete = *filterIncomplete
	case dataset.VulnerabilityDatasetType:
		config.VulnerabilityConfig.SeverityLevel = *severityLevel
		config.VulnerabilityConfig.CWE = *cwe
		config.VulnerabilityConfig.CVE = *cve
	}

	return config
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		Usage()
		os.Exit(1)
	}

	inputPath := args[0]
	if inputPath == "" {
		fmt.Println("Error: Input file path is required")
		Usage()
		os.Exit(1)
	}

	// Create dataset configuration
	config := createDatasetConfig(inputPath)

	// Parse the dataset based on file extension
	ds, err := dataset.ParseDataset(inputPath, config)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to parse dataset: %w", err))
	}

	if *verbose {
		fmt.Println("Parsed dataset:", ds)
	}

	// Create composer
	composer, err := compose.NewComposer(ds, nil)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create composer: %w", err))
	}

	// Get compose configuration string
	composeStr := composer.ComposeStr()

	if *verbose {
		fmt.Println("Generated Docker Compose configuration:")
		fmt.Println(composeStr)
	}

	// Create docker directory if it doesn't exist
	dockerDir := filepath.Join("internal", "docker")
	if err := os.MkdirAll(dockerDir, 0755); err != nil {
		log.Fatal(fmt.Errorf("failed to create docker directory: %w", err))
	}

	// Write compose file
	composeFilePath := filepath.Join(dockerDir, "compose.yaml")
	if err := os.WriteFile(composeFilePath, []byte(composeStr), 0644); err != nil {
		log.Fatal(fmt.Errorf("failed to write compose file: %w", err))
	}
	fmt.Printf("Docker Compose file written to %s\n", composeFilePath)

	// Run all batches with a timeout
	if err := composer.RunBatches(composeFilePath, 50*time.Minute); err != nil {
		log.Fatal(fmt.Errorf("failed to run batches: %w", err))
	}
}
