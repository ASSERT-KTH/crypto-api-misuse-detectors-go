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
	ResultsDir  string
	Parallelism int
	//MetadataWriter *MetadataWriter
}

func NewVulComposer(ds *dataset.VulnerabilityDataset, outDir string, parallelism int) *VulComposer {
	return &VulComposer{
		Dataset:     ds,
		ResultsDir:  filepath.Join(outDir, ds.ID()),
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
	sb := NewServiceBuilder(vc.ResultsDir)

	for pkgIndex, pkg := range vuln.VulPackages {
		if pkg.GitTag == "" {
			fmt.Printf("Warning: skipping package %s with no git tag\n", pkg.Name)
			continue
		}

		// Set default Go version if not specified
		if pkg.GoVersion == "" {
			pkg.GoVersion = DefaultGoVersion
		}

		serviceName := vc.generateUniqueServiceName(vuln.Repo.RepoSlug, strconv.Itoa(vuln.ID), strconv.Itoa(pkgIndex+1))
		service, err := sb.FromVulnerability(vuln, pkg, serviceName)

		if err != nil {
			fmt.Printf("Warning: failed to create service for %s: %v\n", serviceName, err)
			continue
		}
		services.WriteString(service.GenerateStr())
	}
	return services.String()
}

func (vc *VulComposer) generateUniqueServiceName(repo, vulID, pkgID string) string {
	return strings.ToLower(fmt.Sprintf("%s-%s-%s", strings.ReplaceAll(repo, "/", "-"), vulID, pkgID))
}

// RunCompose executes the Docker Compose configuration with parallelism
func (vc *VulComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, vc.Parallelism)
}

func (vc *VulComposer) StopCompose(composeFilePath string) error {
	return StopCompose(composeFilePath)
}
