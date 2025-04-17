package dataset

// DatasetConfig holds configuration options for dataset creation
type DatasetConfig struct {
	// Common configuration options
	Type DatasetType

	// Module dataset specific options
	ModuleConfig *ModuleConfig

	// Vulnerability dataset specific options
	VulnerabilityConfig *VulnerabilityConfig
}

// ModuleConfig holds configuration options specific to module datasets
type ModuleConfig struct {
	// Limit the number of modules to include (e.g., top N by stars)
	Limit int
	// Filter out archived repositories
	FilterArchived bool
	// Filter out educational repositories
	FilterEducational bool
	// Filter out out-of-date repositories
	FilterOutOfDate bool
	// Filter modules without either ReleaseTag or GoVersion
	FilterIncomplete bool
}

// VulnerabilityConfig holds configuration options specific to vulnerability datasets
type VulnerabilityConfig struct {
	// Filter by severity level (e.g., "high", "medium", "low")
	SeverityLevel string
	// Filter by CWE type
	CWE string
	// Filter by CVE
	CVE string
}

// NewModuleConfig creates a new ModuleConfig with default values
func NewModuleConfig() *ModuleConfig {
	return &ModuleConfig{
		Limit:             1500, // Default to top 100
		FilterArchived:    true,
		FilterEducational: true,
		FilterOutOfDate:   true,
	}
}

// NewVulnerabilityConfig creates a new VulnerabilityConfig with default values
func NewVulnerabilityConfig() *VulnerabilityConfig {
	return &VulnerabilityConfig{
		SeverityLevel: "", // No filtering by default
		CWE:           "", // No filtering by default
		CVE:           "", // No filtering by default
	}
}

// NewDatasetConfig creates a new DatasetConfig for the specified dataset type
func NewDatasetConfig(datasetType DatasetType) *DatasetConfig {
	config := &DatasetConfig{
		Type: datasetType,
	}

	switch datasetType {
	case ModuleDatasetType:
		config.ModuleConfig = NewModuleConfig()
	case VulnerabilityDatasetType:
		config.VulnerabilityConfig = NewVulnerabilityConfig()
	}

	return config
}

// NewDatasetConfigFromFile creates a new DatasetConfig based on the file extension
func NewDatasetConfigFromFile(filepath string) *DatasetConfig {
	// Use the existing InferDatasetType function
	datasetType := InferDatasetType(filepath)

	// If the dataset type is empty (unsupported), return a default config
	if datasetType == "" {
		return NewDatasetConfig("")
	}

	return NewDatasetConfig(datasetType)
}
