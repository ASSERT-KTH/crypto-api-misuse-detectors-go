package compose

import (
	"fmt"
	"strings"
)

const (
	DefaultComposeVersion = "3.8"
)

// generateComposeHeader creates the common header for all compose files
func generateComposeHeader() string {
	return fmt.Sprintf("version: '%s'\n\nservices:\n", DefaultComposeVersion)
}

// generateVolumeTopLevel creates the volume configuration for all tools
func generateVolumeTopLevel(c Composer) string {
	var builder strings.Builder
	builder.WriteString("\nvolumes:\n")

	for _, tool := range c.GetConfig().Tools {
		config := tool.GetDockerConfig()
		builder.WriteString(fmt.Sprintf("  %s:\n", tool.Name()))
		builder.WriteString("    driver: local\n")
		builder.WriteString("    driver_opts:\n")
		builder.WriteString("      type: none\n")
		builder.WriteString(fmt.Sprintf("      device: %s\n", config.VolumeTopLevel))
		builder.WriteString("      o: bind\n")
	}

	return builder.String()
}
