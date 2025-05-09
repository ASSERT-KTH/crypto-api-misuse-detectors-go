package sast

// GopherTool is a constant that implements the Tool interface
var GopherTool Tool = gopherTool{}

type gopherTool struct{}

func (gopherTool) Name() string {
	return "gopher"
}

func (gopherTool) GetDockerConfig() DockerConfig {
	return DockerConfig{
		Volumes:   "gopher:/analysis/gopher",
		Command:   "./gopher ../repo && ../rename_json.sh ../repo",
		OutputDir: "/analysis/repo/scan_results",
	}
}
