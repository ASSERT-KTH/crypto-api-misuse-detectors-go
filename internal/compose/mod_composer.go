package compose

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ModComposer implements the Composer interface for module datasets
type ModComposer struct {
	Dataset   *dataset.ModuleDataset
	DatasetID string
	Config    *ComposerConfig
}

func NewModComposer(ds *dataset.ModuleDataset, config *ComposerConfig) *ModComposer {
	if config == nil {
		config = DefaultComposerConfig()
	}
	return &ModComposer{
		Dataset:   ds,
		DatasetID: ds.ID(),
		Config:    config,
	}
}

// GetTotalBatches returns the total number of batches in the compose file
func (mc *ModComposer) GetTotalBatches() int {
	totalModules := mc.Dataset.Count()

	// Calculate total batches, rounding up
	totalBatches := (totalModules + mc.Config.BatchSize - 1) / mc.Config.BatchSize
	if totalBatches < 1 {
		totalBatches = 1 // Ensure at least one batch
	}
	return totalBatches
}

func (mc *ModComposer) ComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	modules := mc.Dataset.GetModules()
	for i, module := range modules {
		// Calculate batch number based on index and batch size
		batchNumber := (i / mc.Config.BatchSize) + 1

		serviceName := generateServiceName(module.RepoName, strconv.Itoa(i+1)) // Use 0 as vulID for modules
		analysisDir := filepath.Join(mc.Config.OutDir, serviceName)
		composeBuilder.WriteString(generateServiceStr(module.URL, module.ReleaseTag, module.GoVersion, serviceName, batchNumber, analysisDir))
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// RunBatches executes all batches in sequence using docker compose
func (mc *ModComposer) RunBatches(composeFilePath string, timeout time.Duration) error {
	return runBatches(composeFilePath, mc.GetTotalBatches(), timeout)
}
