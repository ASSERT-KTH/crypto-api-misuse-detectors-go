package compose

import (
	"path/filepath"
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

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (mc *ModComposer) ComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, mod := range mc.Dataset.GetModules() {
		services := mc.addModServices(mod, mc.DatasetID)
		composeBuilder.WriteString(services)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addModServices adds all services for a single module to the compose file
func (mc *ModComposer) addModServices(mod dataset.Module, datasetID string) string {
	var services strings.Builder

	// Generate service name and paths
	serviceName := generateServiceName(mod.RepoName, "mod0-pkg1")
	analysisDir := filepath.Join(mc.Config.OutDir, serviceName)

	// Add service configuration
	serviceStr := generateServiceStr(mod.URL, mod.ReleaseTag, mod.GoVersion, serviceName, analysisDir)
	services.WriteString(serviceStr)

	return services.String()
}

// RunCompose executes the Docker Compose configuration with parallelism
func (mc *ModComposer) RunCompose(composeFilePath string, timeout time.Duration) error {
	return RunCompose(composeFilePath, mc.Config.Parallelism, timeout)
}
