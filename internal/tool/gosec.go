package tool

import "fmt"

type gosecTool struct{}

func (gosecTool) Name() string {
	return "gosec"
}

func (gosecTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeTopLevel:  fmt.Sprintf("%s/gosec", Toolspath),
		VolumeAttribute: "gosec:/analysis/gosec",
		Command:         []string{"/bin/sh", "-c", "/analysis/gosec/run_gosec.sh"},
	}
}

// String returns a string representation of the DockerConfig
func (gs gosecTool) String() string {
	return fmt.Sprintf("%s: %s", gs.Name(), gs.GetDockerConfig().String())
}

var GoSecTool Tool = gosecTool{}
