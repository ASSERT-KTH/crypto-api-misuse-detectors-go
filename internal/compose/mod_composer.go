package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ModComposer implements the Composer interface for module datasets
type ModComposer struct {
	Dataset     *dataset.ModuleDataset
	OutDir      string
	Parallelism int
}

func NewModComposer(ds *dataset.ModuleDataset, outDir string, parallelism int) *ModComposer {
	return &ModComposer{
		Dataset:     ds,
		OutDir:      outDir,
		Parallelism: parallelism,
	}
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (mc *ModComposer) ComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, mod := range mc.Dataset.GetModules() {
		services := mc.addModServices(mod)
		composeBuilder.WriteString(services)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addModServices adds all services for a single module to the compose file
func (mc *ModComposer) addModServices(mod dataset.Module) string {
	var services strings.Builder

	// Generate service name and paths
	serviceName := generateServiceName(mod.RepoName, "mod0-pkg1")
	analysisDir := filepath.Join(mc.OutDir, serviceName)

	// Write metadata for this package
	metadataWriter := NewMetadataWriter(mc.OutDir)
	if err := metadataWriter.WriteModuleMetadata(mod, serviceName); err != nil {
		fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
	}

	// Add service configuration
	serviceStr := generateServiceStr(mod.URL, mod.ReleaseTag, mod.GoVersion, serviceName, analysisDir)
	services.WriteString(serviceStr)

	return services.String()
}

// RunCompose executes the Docker Compose configuration with parallelism
func (mc *ModComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, mc.Parallelism)
}
