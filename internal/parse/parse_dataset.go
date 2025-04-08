package parse

import (
	"fmt"
	"strings"
)

// DatasetType represents the type of dataset being parsed
type DatasetType string

const (
	VulnerableModuleDatasetType DatasetType = "vulnerability"
	NormalModuleDatasetType     DatasetType = "normal"
)

type Dataset interface {
	// Get the number of items in the dataset
	Count() int
	// Get dataset type description
	Type() string
}

// InferDatasetType determines the type of dataset from the file extension
func InferDatasetType(filepath string) DatasetType {
	ext := strings.ToLower(filepath[strings.LastIndex(filepath, ".")+1:])
	switch ext {
	case "json":
		return VulnerableModuleDatasetType
	case "csv":
		return NormalModuleDatasetType
	default:
		return ""
	}
}

// Parses the data into the appropriate dataset type depending on the dataset type
func ParseDataset(filepath string) (Dataset, error) {
	datasetType := InferDatasetType(filepath)
	switch datasetType {
	case VulnerableModuleDatasetType:
		return ParseVulnerabilities(filepath)
	case NormalModuleDatasetType:
		return ParseNormalModules(filepath)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", filepath)
	}
}
