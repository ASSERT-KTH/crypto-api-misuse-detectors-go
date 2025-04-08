package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/collector"
)

func main() {
	// Define command-line flags
	minStars := flag.Int("min-stars", 500, "Minimum stars for repositories to fetch")
	language := flag.String("lang", "Go", "Programming language to filter by")
	limit := flag.Int("limit", 1500, "Maximum number of repositories to fetch")
	sortBy := flag.String("sort", "stars", "Field to sort by (stars, dependents_count, etc.)")
	outPath := flag.String("out", "", "Output path for the JSON file (default: data/go_repos_{minStars}_stars.json)")
	excludeFile := flag.String("exclude", "", "Path to file containing repository URLs to exclude, one per line")
	maxStars := flag.Int("stars", 100, "Minimum number of stars required for a repository")
	maxAge := flag.Duration("max-age", 365*24*time.Hour, "Maximum age of repository's latest release to consider it active (e.g., 24h, 168h, 720h, 8760h)")

	flag.Parse()

	// Set up the API client
	api := "LIBRARIESIO"
	tokenName := fmt.Sprintf("%s_TOKEN", api)
	apiToken, exists := os.LookupEnv(tokenName)

	if !exists || apiToken == "" {
		log.Fatalf("Error: %s environment variable is not set or is empty\n", tokenName)
	}

	// Create API configuration
	apiCfg := collector.DefaultAPIConfig()

	// Create collector configuration
	collectorCfg := collector.CollectorConfig{
		MinStars:    *minStars,
		Language:    *language,
		SortBy:      *sortBy,
		ReposLimit:  *limit,
		PageSize:    apiCfg.MaxPageSize,
		ExcludeURLs: []string{},
		MaxStars:    *maxStars,
		MaxAge:      *maxAge,
	}

	// Create API client
	client := collector.NewAPIClient(api, apiToken, apiCfg)

	// Determine output directory and file
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory: %v\n", err)
	}

	outdir := filepath.Join(wd, "data")
	if err := os.MkdirAll(outdir, 0755); err != nil {
		log.Fatalf("Error creating output directory: %v\n", err)
	}

	outfileName := fmt.Sprintf("%s_repos_%d_stars.json", strings.ToLower(*language), *minStars)
	if *outPath == "" {
		*outPath = filepath.Join(outdir, outfileName)
	}

	// Load exclude list if provided
	if *excludeFile != "" {
		excludeList, err := loadExcludeList(*excludeFile)
		if err != nil {
			log.Fatalf("Failed to load exclude list: %v\n", err)
		}
		collectorCfg.ExcludeURLs = excludeList
		log.Printf("Loaded %d repositories to exclude\n", len(excludeList))
	} else {
		// Try to load from default config file
		defaultConfig := filepath.Join(wd, "config", "default_excludes.txt")
		excludeList, err := loadExcludeList(defaultConfig)
		if err != nil {
			log.Printf("Warning: Could not load default excludes, using empty list: %v\n", err)
		} else {
			collectorCfg.ExcludeURLs = excludeList
		}
	}

	// Initialize the repository fetcher
	fetcher := collector.NewRepoFetcher(*client, *outPath, collectorCfg)

	if err := fetcher.Validate(); err != nil {
		log.Fatalf("Invalid repository fetcher configuration: %v\n", err)
	}

	// Fetch repositories with star filtering
	log.Printf("Fetching %s repositories with at least %d stars and with releases...\n",
		*language, *minStars)
	if err := fetcher.FetchAndWriteRepos(); err != nil {
		log.Fatalf("Failed to fetch repositories from API: %v\n", err)
	}

	log.Printf("Successfully fetched repositories! Data saved to: %s\n", *outPath)
}

// loadExcludeList loads a list of repository URLs to exclude from a file
func loadExcludeList(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading exclude file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var excludeList []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			excludeList = append(excludeList, line)
		}
	}

	return excludeList, nil
}
