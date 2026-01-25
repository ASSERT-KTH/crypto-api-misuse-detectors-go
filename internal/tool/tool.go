package tool

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

const (
	RepoPathDocker = "/analysis/repo"
	Toolspath      = "${BASE_DIR}/internal/tool"
	CmdShell       = "/bin/sh -c"
)

// Tool represents a SAST analysis tool
type Tool interface {
	// Name returns the name of the tool
	Name() string

	// GetDockerConfig returns the Docker configuration needed for this tool
	// It should return a valid DockerConfig that can be used to run the tool in a container
	GetDockerConfig() DockerConfig

	// String returns a string representation of the tool
	String() string
}

// DockerConfig contains the Docker-specific configuration for a tool
type DockerConfig struct {
	// Command to run the tool, assuming /analysis as WORKDIR
	Command []string `validate:"required"`

	// VolumeTopLevel is the top-level definition of a volume
	VolumeTopLevel string `validate:"required"`

	// VolumeAttribute is the service definition to use a uses a toplevel shared volume
	VolumeAttribute string `validate:"required"`

	// Environment variables to set in the Docker container
	Environment []string

	// Memory contains memory-related settings for the container
	Memory struct {
		// Limit specifies the maximum memory a container can use
		Limit string `validate:"required"`

		// SwapLimit specifies the maximum memory+swap a container can use
		SwapLimit string `validate:"required"`
	} `validate:"required"`
}

// ValidateDockerConfig validates the DockerConfig struct and returns an error if validation fails
func ValidateDockerConfig(dc DockerConfig) error {
	validate := validator.New()
	if err := validate.Struct(dc); err != nil {
		return fmt.Errorf("DockerConfig validation failed: %w", err)
	}
	return nil
}

// String returns a string representation of the DockerConfig
func (dc DockerConfig) String() string {
	return fmt.Sprintf("Command: %v, VolumeTopLevel: %s, VolumeAttribute: %s, Environment: %s", dc.Command, dc.VolumeTopLevel, dc.VolumeAttribute, dc.Environment)
}
