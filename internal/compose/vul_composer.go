package compose

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

const (
	DefaultGoVersion = "1.11"
)

// VulComposer implements the Composer interface for vulnerability datasets
type VulComposer struct {
	Dataset        *dataset.VulnerabilityDataset
	DatasetID      string
	//MetadataWriter *MetadataWriter
}

func NewVulComposer(ds *dataset.VulnerabilityDataset) *VulComposer {
	return &VulComposer{
		Dataset:   ds,
		DatasetID: ds.GetDatasetIdentifier(),
		//MetadataWriter: NewMetadataWriter(ds.GetDatasetIdentifier()),
	}
}

// GenerateComposeStr constructs the complete Docker Compose YAML content as a string
func (vc *VulComposer) GenerateComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, vul := range vc.Dataset.GetVulnerabilities() {
		services := vc.addVulServices(vul, vc.DatasetID)
		composeBuilder.WriteString(services)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addVulServices adds all services for a single vulnerability (potentially multiple packages) to the compose file
func (vc *VulComposer) addVulServices(vul dataset.Vulnerability, datasetID string) string {
	// Create a metadata writer for this vulnerability
	var servicesBuilder strings.Builder

	for packageIndex, vulnPackage := range vul.VulPackages {
		// Skip packages with no identified vulnerable git tags
		if len(vulnPackage.VulGitTags) == 0 {
			continue
		}

		// Set default Go version if not specified
		if vulnPackage.GoVersion == "" {
			vulnPackage.GoVersion = DefaultGoVersion
		}

		// Prepare params for service configuration
		packageID := strconv.Itoa(packageIndex + 1)
		repoSlug := vul.Repo.RepoSlug
		gitTag := vulnPackage.VulGitTags[len(vulnPackage.VulGitTags)-1]
		URL := fmt.Sprintf("https://%s", vul.Repo.RepoSlug)

		serviceName := generateServiceName(repoSlug, packageID)
		resultsDir := generateResultsPath(datasetID, serviceName)

		// // Write a metadata file for this vulnerability package
		// if err := vc.MetadataWriter.WriteMetadata(vulnerability, vulnPackage, packageID); err != nil {
		// 	// Log error but continue with other packages
		// 	fmt.Fprintf(os.Stderr, "Warning: failed to write vulnerability metadata for %s-%d-%d: %v\n",
		// 		vulnerability.Repo.RepoSlug, vulnerability.ID, packageID, err)
		// 	continue
		// }

		// Add service configuration to compose file
		serviceStr := generateServiceStr(URL, gitTag, vulnPackage.GoVersion, serviceName, resultsDir)
		servicesBuilder.WriteString(serviceStr)
	}

	return servicesBuilder.String()
}
