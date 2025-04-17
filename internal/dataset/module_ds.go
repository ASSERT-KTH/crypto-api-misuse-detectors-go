package dataset

import (
	"fmt"
	"os"
	"sort"

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
	Description string `csv:"description"`
	Archived    string `csv:"archived"`
	Educational string `csv:"educational"`
	OutOfDate   string `csv:"outofdate"`
	ReleaseTag  string `csv:"tag"`
	Commit      string `csv:"commit"`
	GoVersion   string `csv:"go_version"`
}

// ModuleDataset implements ProjectDataset for a collection of normal repositories
type ModuleDataset struct {
	Modules []Module
}

func NewModuleDataset(filepath string, config *ModuleConfig) (*ModuleDataset, error) {
	md, err := ParseModules(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse modules: %w", err)
	}

	// Apply filters based on configuration
	if config.FilterArchived {
		md.filterArchived()
	}
	if config.FilterEducational {
		md.filterEducational()
	}
	if config.FilterOutOfDate {
		md.filterOutOfDate()
	}

	if config.FilterIncomplete {
		md.filterIncomplete()
	}

	// Apply limit after filtering
	md.filterTopKStarred(config.Limit)
	return md, nil
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
	if len(md.Modules) == 0 {
		return "NormalModuleDataset{Count: 0}"
	}

	// Take up to 3 samples to show
	sampleSize := 3
	if len(md.Modules) < sampleSize {
		sampleSize = len(md.Modules)
	}

	samples := ""
	for i := 0; i < sampleSize; i++ {
		module := md.Modules[i]
		samples += fmt.Sprintf("\n  %s (Stars: %d, URL: %s)",
			module.RepoName,
			module.Stars,
			module.URL)
	}

	return fmt.Sprintf("NormalModuleDataset{Count: %d, ID: %s, Samples:%s}",
		len(md.Modules), md.ID(),
		samples)
}

// ID returns a string identifier for the dataset
func (md ModuleDataset) ID() string {
	return fmt.Sprintf("%s-%d", md.Type(), md.Count())
}

// GetModules returns the modules in the dataset
func (md *ModuleDataset) GetModules() []Module {
	return md.Modules
}

// ParseModules reads and parses a CSV file containing normal module data
func ParseModules(filepath string) (*ModuleDataset, error) {
	modules, err := ReadModuleCSV(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read normal modules CSV: %w", err)
	}

	md := &ModuleDataset{Modules: modules}
	fmt.Println("Number of modules:", (md.Count()))
	md.filterEducational()
	md.filterOutOfDate()
	md.filterArchived()
	return md, nil
}

// Reads and unmarshals CSV file into a slice of Module structs
func ReadModuleCSV(filepath string) ([]Module, error) {
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

	return modules, nil
}

func filterModules(modules []Module, filterFunc func(Module) bool) []Module {
	var filteredModules []Module
	for _, module := range modules {
		if filterFunc(module) {
			filteredModules = append(filteredModules, module)
		}
	}
	return filteredModules
}

func (md *ModuleDataset) filterEducational() {
	md.Modules = filterModules(md.Modules, func(m Module) bool {
		return m.Educational == "f"
	})
}

func (md *ModuleDataset) filterOutOfDate() {
	md.Modules = filterModules(md.Modules, func(m Module) bool {
		return m.OutOfDate == "f"
	})
}

func (md *ModuleDataset) filterIncomplete() {
	md.Modules = filterModules(md.Modules, func(m Module) bool {
		return m.ReleaseTag != "" && m.GoVersion != ""
	})
}

// filterTopKStarred keeps only the top k modules with the highest star counts
func (md *ModuleDataset) filterTopKStarred(k int) {
	// Sort modules by stars in descending order
	sort.Slice(md.Modules, func(i, j int) bool {
		return md.Modules[i].Stars > md.Modules[j].Stars
	})

	// Keep only the top k modules (or all if we have fewer than k)
	if len(md.Modules) > k {
		md.Modules = md.Modules[:k]
	}
}

func (md *ModuleDataset) filterArchived() {
	md.Modules = filterModules(md.Modules, func(m Module) bool {
		return m.Archived == "f"
	})
}

// WriteModuleCSV writes a slice of modules to a CSV file
func WriteModuleCSV(modules []Module, file *os.File) error {
	return gocsv.MarshalFile(modules, file)
}
