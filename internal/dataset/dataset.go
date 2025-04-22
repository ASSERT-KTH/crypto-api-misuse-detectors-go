package dataset

import (
	"fmt"
)

// DatasetType represents the type of dataset being parsed
type DatasetType string

const (
	VulnerabilityDatasetType DatasetType = "crypto-misuse-cves"
	ModuleDatasetType        DatasetType = "top-starred-modules"
)

type DatasetConfig struct {
	Type DatasetType

	ModuleConfig        *ModuleConfig
	VulnerabilityConfig *VulnerabilityConfig
}

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

// Parses the data into the appropriate dataset type depending on the dataset type
func CreateDataset(path string, cfg *DatasetConfig) (Dataset, error) {
	if cfg == nil {
		panic("dataset config is nil")
	}

	if path == "" {
		return nil, fmt.Errorf("input path is empty")
	}
	switch cfg.Type {
	case VulnerabilityDatasetType:
		return ParseVulnerabilities(path, cfg.VulnerabilityConfig)
	case ModuleDatasetType:
		return NewModuleDataset(path, cfg.ModuleConfig)
	default:
		return nil, fmt.Errorf("unsupported dataset type: %s", cfg.Type)
	}
}
