package dataset

import (
	"fmt"
)

// DatasetType represents the type of dataset being parsed
type DatasetType string

const (
	ModuleDatasetType DatasetType = "top-starred-modules"
)

type Dataset interface {
	// Get the number of items in the dataset
	Count() int
	// Get dataset type description
	Type() DatasetType
	// Stringer
	String() string
	// ID returns a unique identifier for the dataset
	ID() string
}

// CreateDataset is a factory function that creates a dataset based on the type
// This is kept for future extensibility if we need to support more dataset types
func CreateDataset(path string, datasetType DatasetType) (Dataset, error) {
	if path == "" {
		return nil, fmt.Errorf("input path is empty")
	}
	switch datasetType {
	case ModuleDatasetType:
		return NewModuleDataset(path)
	default:
		return nil, fmt.Errorf("unsupported dataset type: %s", datasetType)
	}
}
