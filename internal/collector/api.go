package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/utils"
)

const (
	librariesIOAPIURL = "https://libraries.io/api/search"
	minPageSize       = 1
	maxPageSize       = 1000
)

// APIClient represents a client for making API requests.
type APIClient struct {
	API        string
	APIToken   string
	HTTPClient *http.Client // this is https
}

// ModuleInfoCollector collects repository data.
type ModuleInfoCollector struct {
	Client       APIClient
	Outpath      string
	PageSize     int
	ModulesCount int // number of repositories to collect
}

// Module represents a repository module.
type Module struct {
	ContributionsCount        int    `json:"contributions_count"`
	DependentReposCount       int    `json:"dependent_repos_count"`
	DependentsCount           int    `json:"dependents_count"`
	Description               string `json:"description"`
	Language                  string `json:"language"`
	LatestReleaseNumber       string `json:"latest_release_number"`
	LatestStableReleaseNumber string `json:"latest_stable_release_number"`
	Name                      string `json:"name"`
	PackageManagerURL         string `json:"package_manager_url"`
	Platform                  string `json:"platform"`
	RepositoryURL             string `json:"repository_url"`
	LocalPath                 string
}

// SearchCriteria defines the criteria for searching repositories.
type SearchCriteria struct {
	Platform    string
	SortBy      string
	Order       string
	ExcludeURLs []string
}

// Validate checks the APIClient for required fields.
func (client *APIClient) Validate() error {
	if client.API == "" {
		return fmt.Errorf("API cannot be empty")
	}
	if client.APIToken == "" {
		return fmt.Errorf("API token cannot be empty")
	}
	if client.HTTPClient == nil {
		return fmt.Errorf("HTTP client cannot be nil")
	}
	return nil
}

// Validate checks the RepositoryCollector for required fields.
func (mc *ModuleInfoCollector) Validate() error {
	if mc.ModulesCount <= 0 {
		return fmt.Errorf("ModulesCount must be greater than 0")
	}
	if mc.Outpath == "" {
		return fmt.Errorf("output directory cannot be empty")
	}
	if err := utils.CreateOutputDir(mc.Outpath); err != nil {
		return err
	}
	if mc.PageSize < minPageSize || mc.PageSize > maxPageSize {
		return fmt.Errorf("page size must be between %d and %d", minPageSize, maxPageSize)
	}
	return nil
}

// FetchAndWriteRepoMeta fetches repository metadata and writes it to a file.
func (mc *ModuleInfoCollector) FetchAndWriteRepoMeta(excludeURLs []string) error {
	criteria := SearchCriteria{
		ExcludeURLs: excludeURLs,
		Platform:    "Go",
		SortBy:      "dependents_count",
		Order:       "desc",
	}

	allModules := []Module{}
	numPages := int(math.Ceil(float64(mc.ModulesCount) / float64(mc.PageSize)))

	if numPages < 1 {
		return fmt.Errorf("NumPages must be at least 1")
	}

	for page := 1; page <= numPages; page++ {
		if err := mc.fetchPageData(page, criteria, &allModules); err != nil {
			return err
		}
	}

	return mc.writeJSONToFile(allModules)
}

// fetchPageData fetches data for a specific page and appends it to allModules.
func (mc *ModuleInfoCollector) fetchPageData(page int, criteria SearchCriteria, allModules *[]Module) error {
	url := fmt.Sprintf("%s?order=%s&platforms=%s&sort=%s&per_page=%d&page=%d&api_key=%s",
		librariesIOAPIURL, criteria.Order, criteria.Platform, criteria.SortBy, mc.PageSize, page, mc.Client.APIToken)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	resp, err := mc.Client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed for page %d: %w", page, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) // debugging
		return fmt.Errorf("unexpected status code %d for page %d: %s, response body: %s", resp.StatusCode, page, url, string(body))
	}

	return mc.processResponseBody(resp.Body, criteria, allModules)
}

// processResponseBody processes the response body and filters the modules.
func (mc *ModuleInfoCollector) processResponseBody(body io.Reader, criteria SearchCriteria, allModules *[]Module) error {
	var modules []Module
	if err := json.NewDecoder(body).Decode(&modules); err != nil {
		return fmt.Errorf("unmarshaling JSON: %w", err)
	}

	filteredModules, err := mc.filterModules(modules, criteria)
	if err != nil {
		return fmt.Errorf("failed to filter repositories: %w", err)
	}

	*allModules = append(*allModules, filteredModules...)
	return nil
}

// filterModules filters the modules based on the given criteria.
func (mc *ModuleInfoCollector) filterModules(modules []Module, criteria SearchCriteria) ([]Module, error) {
	var filteredModules []Module
	for _, module := range modules {
		keep, err := module.filterByString("RepositoryURL", criteria.ExcludeURLs)
		if err != nil {
			return nil, err
		}
		if keep {
			localPath, err := module.getFormattedModulePath()
			if err != nil {
				fmt.Println("Warning: error getting local module path: %w", err)
				continue
			}
			module.LocalPath = localPath
			filteredModules = append(filteredModules, module)

		}
	}
	return filteredModules, nil
}

// writeJSONToFile writes the collected modules to a JSON file.
func (mc *ModuleInfoCollector) writeJSONToFile(allModules []Module) error {
	jsonData, err := json.MarshalIndent(allModules, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON data: %w", err)
	}

	if err := os.WriteFile(mc.Outpath, jsonData, 0644); err != nil {
		return fmt.Errorf("writing JSON data to file %s: %w", mc.Outpath, err)
	}

	fmt.Printf("Successfully wrote %d repositories to %s\n", len(allModules), mc.Outpath)
	return nil
}

func (module Module) filterByString(key string, values []string) (bool, error) {
	if len(values) == 0 {
		return true, nil // If no values to filter by, consider the module as valid
	}

	// Create a map for quick lookup
	valueSet := make(map[string]struct{})
	for _, value := range values {
		valueSet[value] = struct{}{}
	}

	var strVal string

	// Access the field based on the key
	switch key {
	case "Name":
		strVal = module.Name
	case "Description":
		strVal = module.Description
	case "RepositoryURL":
		strVal = module.RepositoryURL
	default:
		return false, fmt.Errorf("unsupported key: %s", key)
	}

	// Check if the value exists in the set
	if _, exists := valueSet[strVal]; exists {
		return false, nil // Module matches the filter, return false
	}
	return true, nil // Module does not match the filter, return true
}
