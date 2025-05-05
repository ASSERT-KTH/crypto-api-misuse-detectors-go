package compose

import (
	"fmt"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ModComposer implements the Composer interface for module datasets
type ModComposer struct {
	Dataset *dataset.ModuleDataset
	BaseComposer
}

func NewModComposer(ds *dataset.ModuleDataset, base BaseComposer) *ModComposer {
	return &ModComposer{
		Dataset:      ds,
		BaseComposer: base,
	}
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (mc *ModComposer) ComposeStr() string {
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, mod := range mc.Dataset.GetModules() {
		composeBuilder.WriteString(mc.generateModServices(mod))
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// generateModServices generates services for a single module
func (mc *ModComposer) generateModServices(mod dataset.Module) string {
	var builder strings.Builder
	sb := NewServiceBuilder(mc.ResultsDir, mc.Tools)

	baseServiceName, err := generateServiceName(mod.URL, "")
	if err != nil {
		fmt.Printf("Warning: failed to generate service name for %s: %v\n", mod.URL, err)
		return builder.String()
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
	return RunCompose(composeFilePath, mc.Parallelism)
}

func (mc *ModComposer) StopCompose(composeFilePath string) error {
	return StopCompose(composeFilePath)
}
