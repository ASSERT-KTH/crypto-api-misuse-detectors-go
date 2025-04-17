package dataset

import (
	"fmt"
	"strings"
)

// DatasetType represents the type of dataset being parsed
type DatasetType string

const (
	VulnerabilityDatasetType DatasetType = "crypto-vulnerabilities"
	ModuleDatasetType        DatasetType = "top-starred"
)

type Dataset interface {
	// Get the number of items in the dataset
	Count() int
	// Get dataset type description
	Type() DatasetType
	// Stringer
	String() string
	//
	ID() string
}

// InferDatasetType determines the type of dataset from the file extension
func InferDatasetType(filepath string) DatasetType {
	ext := strings.ToLower(filepath[strings.LastIndex(filepath, ".")+1:])
	switch ext {
	case "json":
		return VulnerabilityDatasetType
	case "csv":
		return ModuleDatasetType
	default:
		return ""
	}
}

// Parses the data into the appropriate dataset type depending on the dataset type
func ParseDataset(filepath string, config *DatasetConfig) (Dataset, error) {
	if config == nil {
		config = NewDatasetConfig(InferDatasetType(filepath))
	}

	switch config.Type {
	case VulnerabilityDatasetType:
		return ParseVulnerabilities(filepath, config.VulnerabilityConfig)
	case ModuleDatasetType:
		if config.ModuleConfig == nil {
			config.ModuleConfig = NewModuleConfig()
		}
		return NewModuleDataset(filepath, config.ModuleConfig)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", filepath)
	}
}
