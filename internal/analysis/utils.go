package main

import (
	"path/filepath"
	"strings"
)

// Takes a filepath as input and returns the base name of the file without its extension.
func getFileName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}
