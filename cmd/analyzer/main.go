package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/analyzer"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please provide the path to the tagged vulnerability JSON file as an argument.")
	}
	vulInfoPath := os.Args[1]

	// read json
	file, err := os.Open(vulInfoPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var vulnerabilities []analyzer.Vulnerability
	// parse into struct
	decoder := json.NewDecoder(file)     // Create a new JSON decoder
	err = decoder.Decode(&vulnerabilities) // Decode JSON into struct
	if err != nil {
		log.Fatal(err) // Handle error
	}

	log.Println("\n\n", vulnerabilities[1]) // Print the vulnerability struct

	// TODO checkout

	// run gopher on it

	// collect the results
}
