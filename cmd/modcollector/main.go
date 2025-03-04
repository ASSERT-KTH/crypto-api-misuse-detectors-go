package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	download "github.com/ASSERT-KTH/go-cryptoapi/internal/collector"
)

func main() {
	api := "LIBRARIESIO" // TODO make this configurable
	tokenName := fmt.Sprintf("%s_TOKEN", api)
	apiToken, exists := os.LookupEnv(tokenName)

	if !exists || apiToken == "" {
		log.Fatalf("Error: %s environment variable is not set or is empty\n", tokenName)
	}

	client := &download.APIClient{
		API:        api,
		APIToken:   apiToken,
		HTTPClient: &http.Client{}, // default HTTP client
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory: %v\n", err)
	}
	outdir := filepath.Join(wd, "data")

	mc := &download.ModuleCollector{
		Outpath:      filepath.Join(outdir, "modules_info.json"),
		Client:       *client,
		PageSize:     100,
		ModulesCount: 1500,
	}

	if err := mc.Validate(); err != nil {
		log.Fatalf("Invalid repository collector configurations: %v\n", err)
	}

	// TODO: if flag fetch modules, do this.
	// exclude := []string{"golang.org", "github.com/golang", "google.golang.org", "cs.opensource.google/go", "github.com/google", "github.com/googleapis"}

	// if err := mc.FetchAndWriteRepoMeta(exclude); err != nil {
	// 	log.Fatalf("Failed to fetch modules from API: %v\n", err)
	// }

	modules, err := download.ParseModules(mc.Outpath)
	if err != nil {
		log.Fatalf("Failed to parse JSON: %v\n", err)
	}
	
	modulesDir := filepath.Join(outdir, "modules")
	modules, err = download.DownloadAll(modules, modulesDir)
	if err != nil {
		log.Fatalf("Failed to download modules: %v\n", err)
	}

	// gopherConf := download.GopherConfig{
	// 	ToolPath:         "",
	// 	Timeout:          135,
	// 	IncludeTestFiles: false,
	// }
	// for _, module := range modules {
	// 	if module.LocalPath != "" {
	// 		// check if the localPath exists
	// 		if _, err := os.Stat(module.LocalPath); err == nil {
	// 			download.RunGopherTool(module, gopherConf)
	// 		} else {
	// 			log.Printf("LocalPath does not exist: %s\n", module.LocalPath)
	// 		}
	// 	}
	// }
}
