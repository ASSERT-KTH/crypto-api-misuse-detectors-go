package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ModComposer implements the Composer interface for module datasets
type ModComposer struct {
	Dataset *dataset.ModuleDataset
	config  Config
}

func NewModComposer(ds *dataset.ModuleDataset, config Config) *ModComposer {
	return &ModComposer{
		Dataset: ds,
		config:  config,
	}
}

// GetConfig returns the composer's configuration
func (mc *ModComposer) GetConfig() Config {
	return mc.config
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (mc *ModComposer) ComposeStr() string {
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, mod := range mc.Dataset.GetModules() {
		composeBuilder.WriteString(mc.generateModServices(mod))
	}

	composeBuilder.WriteString(generateVolumeTopLevel(mc))
	return composeBuilder.String()
}

// generateModServices generates services for a single module
func (mc *ModComposer) generateModServices(mod dataset.Module) string {
	var builder strings.Builder
	sb := NewServiceBuilder(mc.config.Tools, mc.config)

	baseServiceName, err := generateServiceName(mod.URL, "")
	if err != nil {
		fmt.Printf("Warning: failed to generate service name for %s: %v\n", mod.URL, err)
		return builder.String()
	}

	// Write metadata using the existing MetadataWriter
	metadataWriter := getMetadataWriter(mc.config)
	if err := metadataWriter.WriteModuleMetadata(mod, baseServiceName); err != nil {
		fmt.Printf("Warning: failed to write metadata for %s: %v\n", baseServiceName, err)
	}

	toolServices, err := sb.FromModule(mod, baseServiceName)
	if err != nil {
		fmt.Printf("Warning: failed to create services for %s: %v\n", baseServiceName, err)
	} else {
		for _, service := range toolServices {
			builder.WriteString(service.GenerateStr())
		}
	}

	return builder.String()
}

// RunCompose executes the Docker Compose configuration with parallelism
func (mc *ModComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, mc.config.Parallelism)
}

func (mc *ModComposer) StopCompose(composeFilePath string) error {
	return WaitDown(composeFilePath)
}
