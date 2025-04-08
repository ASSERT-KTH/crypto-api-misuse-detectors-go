package parse

import (
	"fmt"
	"os"

	"github.com/gocarina/gocsv"
)

// NormalModule represents data for a single normal repository based on CSV format
type NormalModule struct {
	RepoName    string   `csv:"repo_name"`
	URL         string   `csv:"url"`
	Stars       int      `csv:"stars"`
	LOC         int      `csv:"loc"`
	Size        int      `csv:"size"`
	ForksCount  int      `csv:"forks_count"`
	Issues      int      `csv:"issues"`
	CreatedAt   string   `csv:"created_at"`
	UpdatedAt   string   `csv:"updated_at"`
	PushedAt    string   `csv:"pushed_at"`
	Description string   `csv:"description"`
	Archived    bool     `csv:"archived"`
	Educational bool     `csv:"educational"`
	OutOfDate   bool     `csv:"out_of_date"`
}

// NormalModuleDataset implements ProjectDataset for a collection of normal repositories
type NormalModuleDataset struct {
	Modules []NormalModule
}

// Count returns the number of modules in the dataset
func (nm *NormalModuleDataset) Count() int {
	return len(nm.Modules)
}

// Type returns the type of the dataset
func (nm *NormalModuleDataset) Type() string {
	return "normal"
}

// GetModules returns the modules in the dataset
func (nm *NormalModuleDataset) GetModules() []NormalModule {
	return nm.Modules
}

// Method specific to NormalRepositoryDataset
func (nm *NormalModuleDataset) GetRepositories() []NormalModule {
	return nm.Modules
}

// ParseNormalModules reads and parses a CSV file containing normal module data
func ParseNormalModules(filepath string) (*NormalModuleDataset, error) {
	// Open the CSV file
	file, err := os.OpenFile(filepath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open normal modules file: %w", err)
	}
	defer file.Close()

	// Parse the CSV data
	var modules []NormalModule
	if err := gocsv.UnmarshalFile(file, &modules); err != nil {
		return nil, fmt.Errorf("failed to parse normal modules CSV: %w", err)
	}

	return &NormalModuleDataset{Modules: modules}, nil
}
