package dataset

import (
	"fmt"
	"strings"
)

// DatasetType represents the type of dataset being parsed
type DatasetType string

const (
	VulnerabilityDatasetType DatasetType = "vulnerability"
	ModuleDatasetType        DatasetType = "normal"
)

type Dataset interface {
	// Get the number of items in the dataset
	Count() int
	// Get dataset type description
	Type() DatasetType
	// Stringer
	String() string
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
func ParseDataset(filepath string) (Dataset, error) {
	datasetType := InferDatasetType(filepath)
	switch datasetType {
	case VulnerabilityDatasetType:
		return ParseVulnerabilities(filepath)
	case ModuleDatasetType:
		return ParseModules(filepath)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", filepath)
	}
}
