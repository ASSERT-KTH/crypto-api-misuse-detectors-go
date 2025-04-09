package compose

import (
	"fmt"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

type Composer interface {
	// GenerateComposeStr constructs the complete Docker Compose YAML content as a string
	GenerateComposeStr(outputBasePath string) string
}

// CreateComposer is a factory function that creates the appropriate composer based on dataset type
func CreateComposer(ds dataset.Dataset) (Composer, error) {
	switch ds.Type() {
	case dataset.VulnerabilityDatasetType:
		vulDataset, ok := ds.(*dataset.VulnerableModuleDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *VulnerableModuleDataset, got %T", ds)
		}
		return &VulComposer{Dataset: vulDataset}, nil
	case dataset.ModuleDatasetType:
		modDataset, ok := ds.(*dataset.ModuleDataset)
		if !ok {
			return nil, fmt.Errorf("incompatible dataset type: expected *ModuleDataset, got %T", ds)
		}
		return &ModComposer{Dataset: modDataset}, nil
	default:
		return nil, fmt.Errorf("unknown dataset type: %s", ds.Type())
	}
}

// generateVolumeConfig creates the volume configuration
func generateVolumeConfig() string {
	return `
volumes:
  gopher-shared:
    driver: local
    driver_opts:
      type: none
      device: ${BASE_DIR}/gopher
      o: bind
`
}
