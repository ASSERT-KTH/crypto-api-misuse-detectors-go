package compose

import (
	"fmt"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ComposerConfig holds configuration options for service composition
type ComposerConfig struct {
	// Number of items per batch for parallel processing
	BatchSize int
	OutDir    string
}

// DefaultComposerConfig returns a new ComposerConfig with default values
func DefaultComposerConfig() *ComposerConfig {
	return &ComposerConfig{
		BatchSize: 10, // Default batch size of 10 items
	}
}

type Composer interface {
	// ComposeStr returns the complete Docker Compose YAML content as a string
	// including all services and volume configurations
	ComposeStr() string
	// GetTotalBatches returns the total number of batches in the compose file
	GetTotalBatches() int
	// RunBatches executes all batches in sequence using docker compose
	RunBatches(composeFilePath string, timeout time.Duration) error
	// TODO add "up"
}

// NewComposer is a factory function that creates the appropriate composer based on dataset type
func NewComposer(ds dataset.Dataset, config *ComposerConfig) (Composer, error) {
	if config == nil {
		config = DefaultComposerConfig()
	}

	// Set output directory to dataset ID
	config.OutDir = fmt.Sprintf("data/analysis/%s", ds.ID())

	switch ds.Type() {
	case dataset.VulnerabilityDatasetType:
		vulDataset, ok := ds.(*dataset.VulnerabilityDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *VulnerableModuleDataset, got %T", ds)
		}
		return NewVulComposer(vulDataset, config), nil
	case dataset.ModuleDatasetType:
		modDataset, ok := ds.(*dataset.ModuleDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *ModuleDataset, got %T", ds)
		}
		return NewModComposer(modDataset, config), nil
	default:
		return nil, fmt.Errorf("unknown dataset type: %s", ds.Type())
	}
}
