package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/analyzer"
	"github.com/ASSERT-KTH/go-cryptoapi/internal/utils"

	"golang.org/x/sync/semaphore"
)

func main() {
	vulInfoPath, gopherPath := parseArgs()
	utils.CheckPathExists(vulInfoPath, "vulnerability JSON file")
	utils.CheckPathExists(gopherPath, "gopher path")

	// read json
	file, err := os.Open(vulInfoPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// parse into Vulnerability struct
	var vulnerabilities []analyzer.Vulnerability
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&vulnerabilities)
	if err != nil {
		log.Fatal(err) // Handle error
	}

	// TODO chmod execute for gopher path
	if err = os.Chmod(gopherPath, 0755); err != nil {
		log.Fatalf("Failed to set permissions on %s: %v", gopherPath, err)
	}

	config := analyzer.GopherConfig{
		ToolPath:   gopherPath,
		Timeout:    220 * time.Second,
		MaxThreads: 1,
	}

	fmt.Println(config)

	//var wg sync.WaitGroup // orchestrates multiple runner.run
	// new gopher runner with repo locks and semaphore (shared)
	_ = &analyzer.GopherRunner{
		Config:    config,
		Sem:       semaphore.NewWeighted(int64(config.MaxThreads)),
		RepoLocks: sync.Map{},
	}

	// // analyze each vulnerability in parallel, hoping they do not lock the same repo
	// for _, v := range vulnerabilities {
	// 	wg.Add(1)
	// 	go v.AnalyzeVulnerability(&wg, runner) // finishes after all packages analyzed
	// }
	// wg.Wait()
	// log.Print("All vulnerabilities analyzed.")

	// collect the results

}

func parseArgs() (string, string) {
	if len(os.Args) < 3 {
		log.Fatal("Usage: analyzer <path_to_vulnerability_json_with_tags> <gopher_path>")
	}
	return os.Args[1], os.Args[2]
}
