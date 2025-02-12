package collector

import (
	"os"
	"path/filepath"
)

// createOutputDir creates the output directory if it doesn't exist.
func createOutputDir(outpath string) error {
	dirPath := filepath.Dir(outpath)
	return os.MkdirAll(dirPath, 0755)
}
