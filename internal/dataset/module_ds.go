package dataset

import (
	"fmt"
	"os"

	"github.com/gocarina/gocsv"
)

// Module represents data for a single normal repository based on CSV format
type Module struct {
	ID          string `csv:"id"`
	RepoName    string `csv:"repo_name"`
	URL         string `csv:"url"`
	Stars       int    `csv:"stars"`
	LOC         int    `csv:"loc"`
	Size        int    `csv:"size"`
	ForksCount  int    `csv:"forks_count"`
	Issues      int    `csv:"issues"`
	CreatedAt   string `csv:"created_at"`
	UpdatedAt   string `csv:"updated_at"`
	PushedAt    string `csv:"pushed_at"`
	Description string `csv:"description"`
	Archived    bool   `csv:"archived"`
	Educational bool   `csv:"educational"`
	OutOfDate   bool   `csv:"out_of_date"`
	LatestTag   string // TODO how to get latest tag
	GoVersion   string // TODO how to get Go version
}

// ModuleDataset implements ProjectDataset for a collection of normal repositories
type ModuleDataset struct {
	Modules []Module
}

// Count returns the number of modules in the dataset
func (md ModuleDataset) Count() int {
	return len(md.Modules)
}

// Type returns the type of the dataset
func (md ModuleDataset) Type() DatasetType {
	return ModuleDatasetType
}

// String returns a string representation of the normal module
func (md ModuleDataset) String() string {
	return fmt.Sprintf("NormalModuleDataset{Count: %d}", len(md.Modules))
}

// GetDatasetIdentifier returns a string identifier for the dataset
func (md ModuleDataset) GetDatasetIdentifier() string {
	return fmt.Sprintf("%s-%d", md.Type(), md.Count())
}

// TODO generalise for interface
// GetModules returns the modules in the dataset
func (md *ModuleDataset) GetModules() []Module {
	return md.Modules
}

// ParseModules reads and parses a CSV file containing normal module data
func ParseModules(filepath string) (*ModuleDataset, error) {
	// Open the CSV file
	file, err := os.OpenFile(filepath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open normal modules file: %w", err)
	}
	defer file.Close()

	// Parse the CSV data
	var modules []Module
	if err := gocsv.UnmarshalFile(file, &modules); err != nil {
		return nil, fmt.Errorf("failed to parse normal modules CSV: %w", err)
	}

	return &ModuleDataset{Modules: modules}, nil
}
