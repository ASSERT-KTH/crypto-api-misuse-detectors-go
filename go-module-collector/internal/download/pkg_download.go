package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

var moduleBasePath = filepath.Join(os.Getenv("GOPATH"), "pkg/mod")

func ParseModules(filepath string) ([]Module, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filepath, err)
	}

	var modules []Module
	if err := json.Unmarshal(data, &modules); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON data: %w", err)
	}

	return modules, nil
}

func DownloadAll(modules []Module, outdir string) ([]Module, error) {
	err := os.Setenv("GOMODCACHE", outdir)
	if err != nil {
		return nil, fmt.Errorf("error setting GOMODCACHE to %s: %w", outdir, err)
	}

	maxThreads := 10
	semaphore := make(chan struct{}, maxThreads)
	var wg sync.WaitGroup	
	errChan := make(chan error, len(modules))

	for _, module := range modules {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(m Module) {
			defer wg.Done()
			defer func() { <-semaphore }()
			if err := module.download(); err != nil {
				//log.Printf("Warning: failed to download module %s: %w", module.Name, err)
				errChan <- err
			}
		}(module)
	}
	wg.Wait()
	close(errChan)

	var errs []error
	for e := range errChan {
		errs = append(errs, e)
	}

	if len(errs) > 0 {
		return modules, fmt.Errorf("some downloads failed: %v", errs)
	}

	return modules, nil
}

func (repo *Module) download() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30) 
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "get", fmt.Sprintf("%s@%s", repo.Name, repo.LatestReleaseNumber))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error downloading repository: %w, output: %s", err, output)
	}

	fmt.Printf("Successfully downloaded %s at version %s\n", repo.RepositoryURL, repo.LatestReleaseNumber)
	return nil
}

func (module *Module) getFormattedModulePath() (string, error) {
	if moduleBasePath == "" {
		return "", fmt.Errorf("moduleBasePath is empty")
	}
	formattedName := cleanRepoName(module)
	modulePath := filepath.Join(moduleBasePath, formattedName+"@"+module.LatestReleaseNumber)
	return modulePath, nil
}

// go uses some naming scheme for capitalized package name for modules
func cleanRepoName(repo *Module) string {
	var processedName strings.Builder

	for _, char := range repo.Name {
		if unicode.IsUpper(char) {
			processedName.WriteRune('!')
			processedName.WriteRune(unicode.ToLower(char))
		} else {
			processedName.WriteRune(char)
		}
	}

	return processedName.String()
}
