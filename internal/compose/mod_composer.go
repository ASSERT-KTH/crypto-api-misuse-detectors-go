package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/sast"
)

// ModComposer implements the Composer interface for module datasets
type ModComposer struct {
	Dataset     *dataset.ModuleDataset
	ResultsDir  string
	Parallelism int
	Tools       []sast.Tool
}

func NewModComposer(ds *dataset.ModuleDataset, outDir string, parallelism int) *ModComposer {
	return &ModComposer{
		Dataset:     ds,
		ResultsDir:  filepath.Join(outDir, ds.ID()),
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
	sb := NewServiceBuilder(mc.ResultsDir)
	serviceName := mc.generateUniqueServiceName(mod.URL)
	service, err := sb.FromModule(mod, serviceName)

	if err != nil {
		fmt.Printf("Warning: failed to create service for %s: %v\n", serviceName, err)
	} else {
		services.WriteString(service.GenerateStr())
	}
	return services.String()
}

func (mc *ModComposer) generateUniqueServiceName(repoURL string) string {
	cleanPrefix := strings.TrimPrefix(strings.TrimPrefix(repoURL, "https://"), "http://")
	cleanURL := strings.ReplaceAll(cleanPrefix, "/", "-")
	return strings.ToLower(cleanURL)
}

// RunCompose executes the Docker Compose configuration with parallelism
func (mc *ModComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, mc.Parallelism)
}

func (mc *ModComposer) StopCompose(composeFilePath string) error {
	return StopCompose(composeFilePath)
}
