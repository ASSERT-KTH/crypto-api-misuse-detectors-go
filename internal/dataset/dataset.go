package dataset

import (
	"fmt"
	"strings"
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
func CreateDataset(path string, cfg *DatasetConfig) (Dataset, error) {
	if cfg == nil {
		panic("dataset config is nil")
	}

	if path == "" {
		return nil, fmt.Errorf("input path is empty")
	}

	fmt.Print(string(cfg.Type))
	switch cfg.Type {
	case VulnerabilityDatasetType:
		return ParseVulnerabilities(path, cfg.VulnerabilityConfig)
	case ModuleDatasetType:
		return NewModuleDataset(path, cfg.ModuleConfig)
	default:
		return nil, fmt.Errorf("unsupported dataset type: %s", cfg.Type)
	}
}
