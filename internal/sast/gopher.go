package sast

import "fmt"

type gopherTool struct{}

func (gopherTool) Name() string {
	return "gopher"
}

func (gopherTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		VolumeName:      "gopher",
		VolumeTopLevel:  fmt.Sprintf("%s/gopher", Toolspath),
		VolumeAttribute: "gopher:/analysis/gopher",
		Command:         "cd /analysis/gopher && ./gopher ../repo && ./rename_json.sh ../repo",
		ResultsDir:      "/analysis/repo/scan_results",
	}
}

// GopherTool is a constant that implements the Tool interface
var GopherTool Tool = gopherTool{}
