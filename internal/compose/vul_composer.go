package compose

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

const (
	DefaultGoVersion = "1.11"
)

// VulComposer implements the Composer interface for vulnerability datasets
type VulComposer struct {
	Dataset     *dataset.VulnerabilityDataset
	OutDir      string
	Parallelism int
	//MetadataWriter *MetadataWriter
}

func NewVulComposer(ds *dataset.VulnerabilityDataset, outdir string, parallelism int) *VulComposer {
	return &VulComposer{
		Dataset:     ds,
		OutDir:      outdir,
		Parallelism: parallelism,
	}
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (vc *VulComposer) ComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, vul := range vc.Dataset.GetVulnerabilities() {
		services := vc.addVulServices(vul)
		composeBuilder.WriteString(services)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addVulServices adds all services for a single vulnerability (potentially multiple packages) to the compose file
func (vc *VulComposer) addVulServices(vuln dataset.Vulnerability) string {
	var services strings.Builder

	for pkgIndex, pkg := range vuln.VulPackages {
		// Skip packages with no identified vulnerable git tags
		if pkg.GitTag == "" {
			fmt.Printf("Warning: skipping package %s with no git tag\n", pkg.Name)
			continue
		}

		// Set default Go version if not specified
		if pkg.GoVersion == "" {
			pkg.GoVersion = DefaultGoVersion
		}

		// Generate service name and paths
		vulnID := strconv.Itoa(vuln.ID)
		pkgID := strconv.Itoa(pkgIndex + 1) // 1-based index for better readability
		uniqueID := fmt.Sprintf("%s-%s", vulnID, pkgID)
		serviceName := generateServiceName(vuln.Repo.RepoSlug, uniqueID)
		analysisDir := filepath.Join(vc.OutDir, serviceName)

		// Write metadata for this package
		metadataWriter := NewMetadataWriter(vc.OutDir)
		if err := metadataWriter.WriteVulMetadata(vuln, pkg, serviceName); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
		}

		// Add service configuration
		serviceStr := generateServiceStr(vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, serviceName, analysisDir)
		services.WriteString(serviceStr)
	}

	return services.String()
}

// RunCompose executes the Docker Compose configuration with parallelism
func (vc *VulComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, vc.Parallelism)
}
