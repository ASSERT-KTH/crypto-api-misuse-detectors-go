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

// Config holds application-level configuration
type Config struct {
	// Dataset configuration
	DatasetConfig *dataset.DatasetConfig

	// Execution configuration
	Verbose     bool
	Parallelism int
	Timeout     time.Duration
	DockerDir   string
}

// parseFlags parses command line flags and returns configuration
func parseFlags() (*Config, string, error) {
	// Create base dataset config
	dsConfig := &dataset.DatasetConfig{
		ModuleConfig: &dataset.ModuleConfig{
			Limit:             *flag.Int("module-limit", 550, "Limit the number of modules to include (top N by stars)"),
			FilterArchived:    *flag.Bool("no-archived", true, "Filter out archived repositories"),
			FilterEducational: *flag.Bool("no-educational", true, "Filter out educational repositories"),
			FilterOutOfDate:   *flag.Bool("no-out-of-date", true, "Filter out out-of-date repositories"),
			FilterIncomplete:  *flag.Bool("no-incomplete", true, "Filter out incomplete repositories"),
		},
		VulnerabilityConfig: &dataset.VulnerabilityConfig{
			SeverityLevel: *flag.String("severity", "", "Filter vulnerabilities by severity level (e.g., high, medium, low)"),
			CWE:           *flag.String("cwe", "", "Filter vulnerabilities by CWE type"),
			CVE:           *flag.String("cve", "", "Filter vulnerabilities by CVE"),
		},
	}

	// Create application config
	config := &Config{
		DatasetConfig: dsConfig,
		Verbose:       *flag.Bool("verbose", true, "Enable verbose output"),
		Parallelism:   *flag.Int("parallel", 4, "Number of parallel operations for Docker Compose"),
		Timeout:       *flag.Duration("timeout", 50*time.Minute, "Timeout for Docker Compose execution"),
		DockerDir:     *flag.String("docker-dir", "internal/docker", "Directory for Docker files"),
	}

	// flag.Usage = func() {
	// 	fmt.Println("Usage: ./cryptoanalysis [options] <input_file>")
	// 	fmt.Println("\nOptions:")
	// 	flag.PrintDefaults()
	// 	fmt.Println("\nInput file types:")
	// 	fmt.Println("  .json - Vulnerability specification")
	// 	fmt.Println("  .csv  - Go modules specification")
	// 	fmt.Println("\nExamples:")
	// 	fmt.Println("  ./cryptoanalysis -module-limit=500 -filter-archived=true modules.csv")
	// 	fmt.Println("  ./cryptoanalysis -severity=high -cwe=CWE-327 vulnerabilities.json")
	// }

	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		return nil, "", fmt.Errorf("input file path is required")
	}

	return config, args[0], nil
}

func main() {
	config, datasetFilePath, err := parseFlags()
	if err != nil {
		fmt.Println("Error:", err)
		flag.Usage()
		os.Exit(1)
	}

	// Parse the dataset based on file extension
	ds, err := dataset.ParseDataset(datasetFilePath, config.DatasetConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to parse dataset: %w", err))
	}

	if config.Verbose {
		fmt.Println("Parsed dataset:", ds)
	}

	// Create composer with parallelism configuration
	composerConfig := compose.DefaultComposerConfig()
	composerConfig.Parallelism = config.Parallelism
	composer := compose.NewComposer(ds, composerConfig)

	// Get compose configuration string
	composeStr := composer.ComposeStr()

	if config.Verbose {
		fmt.Println("Generated Docker Compose configuration:")
		fmt.Println(composeStr)
	}

	// Create docker directory if it doesn't exist
	if err := os.MkdirAll(config.DockerDir, 0755); err != nil {
		log.Fatal(fmt.Errorf("failed to create docker directory: %w", err))
	}

	// Write compose file
	composeFilePath := filepath.Join(config.DockerDir, "compose.yaml")
	if err := os.WriteFile(composeFilePath, []byte(composeStr), 0644); err != nil {
		log.Fatal(fmt.Errorf("failed to write compose file: %w", err))
	}
	fmt.Printf("Docker Compose file written to %s\n", composeFilePath)

	// Run Docker Compose with parallelism
	if err := composer.RunCompose(composeFilePath, config.Timeout); err != nil {
		log.Fatal(fmt.Errorf("failed to run Docker Compose: %w", err))
	}
}
