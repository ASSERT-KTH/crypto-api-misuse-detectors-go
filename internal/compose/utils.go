package compose

import (
	"fmt"
	"path/filepath"
	"strings"
)

// generatePackageAnalysisPath generates the repository relative directory path for storing a package's analysis results
func generatePackageAnalysisPath(baseName string, repoSlug string, id int, pkgNum int) string {
	return fmt.Sprintf("data/analysis/cve/%s/%s-%d-%d",
		baseName,
		strings.ReplaceAll(repoSlug, "/", "-"),
		id,
		pkgNum)
}

// Takes a filepath as input and returns the base name of the file without its extension.
func GetFileName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

