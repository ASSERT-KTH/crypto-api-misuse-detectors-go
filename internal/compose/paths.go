package compose

import "path/filepath"

// PathConfig defines the base paths used in the application
type PathConfig struct {
	// BaseDir is the root directory for all Docker-related files
	// This is set via the BASE_DIR environment variable in Docker
	BaseDir string

	// ResultsDir is the directory where analysis results are stored
	// This is relative to the host filesystem
	ResultsDir string
}

// DefaultPaths returns the default path configuration
func DefaultPaths() PathConfig {
	return PathConfig{
		BaseDir:    "${BASE_DIR}", // Used in Docker compose files
		ResultsDir: "results",     // Used in host filesystem
	}
}

// ContainerPaths defines the paths used inside containers
type ContainerPaths struct {
	// AnalysisDir is the base directory for analysis in containers
	AnalysisDir string
	// RepoDir is where the repository is cloned
	RepoDir string
	// ResultsDir is where tools write their results
	ResultsDir string
}

// DefaultContainerPaths returns the default container path configuration
func DefaultContainerPaths() ContainerPaths {
	return ContainerPaths{
		AnalysisDir: "/analysis",
		RepoDir:     "/analysis/repo",
		ResultsDir:  "/analysis/results",
	}
}

// ServicePaths represents the paths for a specific service
type ServicePaths struct {
	// HostResultsPath is the full path on the host where results will be stored
	HostResultsPath string
	// ContainerResultsPath is the path in the container where results will be mounted
	ContainerResultsPath string
}

// NewServicePaths creates a new ServicePaths instance for a specific service
func NewServicePaths(pc PathConfig, cp ContainerPaths, datasetDir, repoID, toolName string) ServicePaths {
	// Host path is under the base directory
	hostPath := filepath.Join(pc.BaseDir, "results", datasetDir, repoID, toolName)

	// Container path is under the analysis directory
	containerPath := filepath.Join(cp.ResultsDir, toolName)

	return ServicePaths{
		HostResultsPath:      hostPath,
		ContainerResultsPath: containerPath,
	}
}
