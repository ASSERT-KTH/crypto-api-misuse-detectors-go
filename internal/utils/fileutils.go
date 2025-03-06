package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// check if the paths exist and log errors
func CheckPathExists(path string, pathType string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Fatalf("The specified %s does not exist: %s", pathType, path)
	}
}

// createOutputDir creates the output directory if it doesn't exist.
func CreateOutputDir(outpath string) error {
	dirPath := filepath.Dir(outpath)
	return os.MkdirAll(dirPath, 0755)
}

func FindChildDir(parentDir string) (string, error) {
	files, err := os.ReadDir(parentDir)

	if err != nil {
		return "", fmt.Errorf("failed to read directory %s: %w", parentDir, err)
	}
	
	if len(files) > 1 {
		return "", fmt.Errorf("No child")
	}
	for _, file := range files {
		if file.IsDir() {
			return filepath.Join(parentDir, file.Name()), nil
		}
	}

	return "", fmt.Errorf("no child directories found in %s", parentDir)
}
