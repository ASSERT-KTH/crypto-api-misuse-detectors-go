package compose

import (
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// ModComposer implements the Composer interface for normal modules datasets
type ModComposer struct {
	Dataset *dataset.ModuleDataset
	DatasetID string

}

func NewModComposer(ds *dataset.ModuleDataset) *ModComposer {
	return &ModComposer{
		Dataset: ds,
		DatasetID: ds.GetDatasetIdentifier(),
	}
}

func (mc *ModComposer) GenerateComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())
	
	for _, module := range mc.Dataset.GetModules() {
		serviceName := generateServiceName(module.RepoName, module.ID)
		resultsDir := generateResultsPath(mc.DatasetID, serviceName)

		// generate service string
		serviceConfig := generateServiceStr(module.URL, module.LatestTag, module.GoVersion, serviceName, resultsDir)
		composeBuilder.WriteString(serviceConfig)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}
