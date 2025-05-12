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
	Dataset *dataset.VulnerabilityDataset
	config  Config
}

func NewVulComposer(ds *dataset.VulnerabilityDataset, config Config) *VulComposer {
	return &VulComposer{
		Dataset: ds,
		config:  config,
	}
}

// GetConfig returns the composer's configuration
func (vc *VulComposer) GetConfig() Config {
	return vc.config
}

// ComposeStr constructs the complete Docker Compose YAML content as a string
func (vc *VulComposer) ComposeStr() string {
	var composeBuilder strings.Builder
	composeBuilder.WriteString(generateComposeHeader())

	for _, vul := range vc.Dataset.GetVulnerabilities() {
		composeBuilder.WriteString(vc.generateVulServices(vul))
	}

	composeBuilder.WriteString(generateVolumeTopLevel(vc))
	return composeBuilder.String()
}

// generateVulServices generates services for a single vulnerability
func (vc *VulComposer) generateVulServices(vul dataset.Vulnerability) string {
	var builder strings.Builder
	sb := NewServiceBuilder(vc.config.Tools)

	for i, pkg := range vul.VulPackages {
		if pkg.GitTag == "" {
			fmt.Printf("Warning: skipping package %s with no git tag\n", pkg.Name)
			continue
		}

		builder.WriteString(vc.generatePkgServices(sb, vul, pkg, i))
	}

	return builder.String()
}

// generatePkgServices generates services for a single package
func (vc *VulComposer) generatePkgServices(sb *ServiceBuilder, vul dataset.Vulnerability, pkg dataset.VulPackage, pkgIndex int) string {
	var builder strings.Builder

	pkgID := fmt.Sprintf("%s-%d", strconv.Itoa(vul.ID), pkgIndex+1)
	baseServiceName, err := generateServiceName(vul.Repo.URL, pkgID)
	if err != nil {
		fmt.Printf("Warning: failed to generate service name for %s: %v\n", pkgID, err)
		return builder.String()
	}

	if pkg.GoVersion == "" {
		pkg.GoVersion = DefaultGoVersion
	}
	toolServices, err := sb.FromVulnerability(vul, pkg, baseServiceName)
	if err != nil {
		fmt.Printf("Warning: failed to create services for %s: %v\n", baseServiceName, err)
		return builder.String()
	}

	for _, service := range toolServices {
		builder.WriteString(service.GenerateStr())
	}

	return builder.String()
}

// RunCompose executes the Docker Compose configuration with parallelism
func (vc *VulComposer) RunCompose(composeFilePath string) error {
	return RunCompose(composeFilePath, vc.config.Parallelism)
}

func (vc *VulComposer) StopCompose(composeFilePath string) error {
	return StopCompose(composeFilePath)
}
