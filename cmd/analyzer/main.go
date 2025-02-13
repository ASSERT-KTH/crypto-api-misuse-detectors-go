package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/analyzer"
)

func main() {
	vulInfoPath, gopherPath := parseArgs()
	checkPathExists(vulInfoPath, "vulnerability JSON file")
	checkPathExists(gopherPath, "gopher path")

	// read json
	file, err := os.Open(vulInfoPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var vulnerabilities []analyzer.Vulnerability
	// parse into struct
	decoder := json.NewDecoder(file)       // Create a new JSON decoder
	err = decoder.Decode(&vulnerabilities) // Decode JSON into struct
	if err != nil {
		log.Fatal(err) // Handle error
	}

	config := analyzer.GopherConfig{
		ToolPath:   gopherPath, // Construct the path to gopher
		Timeout:    2 * time.Second,
		MaxThreads: 5,
	}

	fmt.Println(config)
	// run gopher for all vuls
	// collect the results
}


// parseArgs retrieves command line arguments and checks their validity
func parseArgs() (string, string) {
	if len(os.Args) < 3 {
		log.Fatal("Please provide the path to the tagged vulnerability JSON file and the gopher path as arguments.")
	}
	return os.Args[1], os.Args[2]
}

// check if the paths exist and log errors
func checkPathExists(path string, pathType string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Fatalf("The specified %s does not exist: %s", pathType, path)
	}
}
