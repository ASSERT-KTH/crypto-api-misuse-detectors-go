package compose

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

const (
	DefaultGoVersion = "1.11"
)

// VulComposer implements the Composer interface for vulnerability datasets
type VulComposer struct {
	Dataset   *dataset.VulnerabilityDataset
	DatasetID string
	Config    *ComposerConfig
	//MetadataWriter *MetadataWriter
}

func NewVulComposer(ds *dataset.VulnerabilityDataset, config *ComposerConfig) *VulComposer {
	if config == nil {
		config = DefaultComposerConfig()
	}
	return &VulComposer{
		Dataset:   ds,
		DatasetID: ds.ID(),
		Config:    config,
		//MetadataWriter: NewMetadataWriter(ds.GetDatasetIdentifier()),
	}
}

// GetTotalBatches returns the total number of batches in the compose file
func (vc *VulComposer) GetTotalBatches() int {
	totalPackages := vc.Dataset.Count()

	// Calculate total batches, rounding up
	totalBatches := (totalPackages + vc.Config.BatchSize - 1) / vc.Config.BatchSize
	if totalBatches < 1 {
		totalBatches = 1 // Ensure at least one batch
	}
	return totalBatches
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (vc *VulComposer) ComposeStr() string {
	// Generate the Docker Compose YAML content
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	// Track total package index across all vulnerabilities
	totalPackageIndex := 0

	for _, vul := range vc.Dataset.GetVulnerabilities() {
		services := vc.addVulServices(vul, vc.DatasetID, &totalPackageIndex)
		composeBuilder.WriteString(services)
	}

	composeBuilder.WriteString(generateVolumeConfig())
	return composeBuilder.String()
}

// addVulServices adds all services for a single vulnerability (potentially multiple packages) to the compose file
func (vc *VulComposer) addVulServices(vuln dataset.Vulnerability, datasetID string, totalPkgIndex *int) string {
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

		// Calculate batch number based on total package index and batch size
		batchNum := (*totalPkgIndex / vc.Config.BatchSize) + 1
		*totalPkgIndex++

		// Generate service name and paths
		vulnID := strconv.Itoa(vuln.ID)
		pkgID := strconv.Itoa(pkgIndex + 1) // 1-based index for better readability
		uniqueID := fmt.Sprintf("%s-%s", vulnID, pkgID)
		serviceName := generateServiceName(vuln.Repo.RepoSlug, uniqueID)
		analysisDir := filepath.Join(vc.Config.OutDir, serviceName)

		// Write metadata for this package
		metadataWriter := NewMetadataWriter(vc.Config.OutDir)
		if err := metadataWriter.WriteMetadata(vuln, pkg, serviceName); err != nil {
			fmt.Printf("Warning: failed to write metadata for %s: %v\n", serviceName, err)
		}

		// Add service configuration
		serviceStr := generateServiceStr(vuln.Repo.URL, pkg.GitTag, pkg.GoVersion, serviceName, batchNum, analysisDir)
		services.WriteString(serviceStr)
	}

	return services.String()
}

// RunBatches executes all batches in sequence using docker compose
func (vc *VulComposer) RunBatches(composeFilePath string, timeout time.Duration) error {
	return runBatches(composeFilePath, vc.GetTotalBatches(), timeout)
}
