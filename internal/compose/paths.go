package compose

import "path/filepath"

// Constants for container paths
const (
	// Base directory for Docker files (used in compose files)
	BaseDir = "${BASE_DIR}"

	// Container paths that are fixed
	ContainerResultsDir = "/analysis/results"
)

// ServicePaths represents the paths for a specific service
type ServicePaths struct {
	// HostResultsPath is the full path on the host where results will be stored
	HostResultsPath string
	// ContainerResultsPath is the path in the container where results will be mounted
	ContainerResultsPath string
}

// NewServicePaths creates a new ServicePaths instance for a specific service.
// It constructs the paths needed for mounting results between the host and container.
// The paths are structured as:
// - Host: ${BASE_DIR}/resultsDir/repoID/toolName
// - Container: /analysis/results/toolName
func NewServicePaths(resultsDir, repoID, toolName string) ServicePaths {
	if resultsDir == "" {
		panic("results directory cannot be empty")
	}

	return ServicePaths{
		HostResultsPath:      filepath.Join(BaseDir, resultsDir, repoID, toolName),
		ContainerResultsPath: filepath.Join(ContainerResultsDir, toolName),
	}
}
