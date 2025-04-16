package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset/goversion"
	"github.com/gocarina/gocsv"
)

func main() {
	// Define command line flags
	inputFile := flag.String("input", "", "Path to input CSV file")
	outputFile := flag.String("output", "", "Path to output CSV file (defaults to input_augmented.csv)")
	concurrency := flag.Int("concurrency", 5, "Number of concurrent API requests")
	flag.Parse()

	// Validate flags
	if *inputFile == "" {
		fmt.Println("Error: input file is required")
		fmt.Println("Usage: go run main.go -input=modules.csv [-output=output.csv] [-concurrency=5]")
		os.Exit(1)
	}

	// Set default output file if not specified
	if *outputFile == "" {
		ext := filepath.Ext(*inputFile)
		base := (*inputFile)[:len(*inputFile)-len(ext)]
		*outputFile = base + "_augmented" + ext
	}

	// Read and parse the CSV file
	fmt.Printf("Loading modules from %s...\n", *inputFile)
	startTime := time.Now()

	moduleDataset, err := dataset.ParseModules(*inputFile)
	if err != nil {
		fmt.Printf("Error parsing module data: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d modules in %v\n", moduleDataset.Count(), time.Since(startTime))

	// Augment modules with commit info and Go versions
	fmt.Printf("Augmenting modules with commit info and Go versions (concurrency: %d)...\n", *concurrency)
	startTime = time.Now()

	// Get the modules from the dataset
	modules := moduleDataset.GetModules()

	// Augment modules with the goversion package
	augmentedModules, err := goversion.AugmentModules(modules, *concurrency)
	if err != nil {
		// Just print a warning, we still want to save any modules that were successfully processed
		fmt.Printf("Warning: some errors occurred during augmentation\n")
	}

	fmt.Printf("Augmentation completed in %v\n", time.Since(startTime))

	// Count how many modules have Go versions
	goVersionCount := 0
	for _, module := range augmentedModules {
		if module.GoVersion != "" {
			goVersionCount++
		}
	}
	fmt.Printf("Successfully found Go versions for %d of %d modules\n", goVersionCount, len(augmentedModules))

	// Save the augmented modules to CSV
	fmt.Printf("Saving augmented modules to %s...\n", *outputFile)

	// Create output file
	file, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Marshal the augmented modules to CSV
	if err := gocsv.MarshalFile(augmentedModules, file); err != nil {
		fmt.Printf("Error writing CSV data: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully saved augmented modules to %s\n", *outputFile)
}
