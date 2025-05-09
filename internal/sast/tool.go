package sast

// Tool represents a SAST analysis tool
type Tool interface {
	Name() string

	// GetDockerConfig returns the Docker configuration needed for this tool
	GetDockerConfig() DockerConfig
}

// DockerConfig contains the Docker-specific configuration for a tool
type DockerConfig struct {
	// Volumes are the volume mounts needed
	Volumes string

	// Command to run the tool
	Command string

	// OutputDir specifies where the tool writes its results in the container
	// This will be mounted to the local results directory
	OutputDir string
}
