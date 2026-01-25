package tool

import "fmt"

type gopherTool struct{}

func (gopherTool) Name() string {
	return "gopher"
}

func (gopherTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeTopLevel:  fmt.Sprintf("%s/gopher", Toolspath),
		VolumeAttribute: "gopher:/analysis/gopher",
		Command:         []string{"/bin/sh", "-c", "/analysis/gopher/run_gopher.sh"},
	}
}


// String returns a string representation of the DockerConfig
func (gt gopherTool) String() string {
	return fmt.Sprintf("%s: %s", gt.Name(), gt.GetDockerConfig().String())
}

var GopherTool Tool = gopherTool{}
