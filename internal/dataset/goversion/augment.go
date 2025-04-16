package goversion

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// AugmentModules adds latest commit hash and Go version to modules
// concurrency controls how many requests can be in flight at once
func AugmentModules(modules []dataset.Module, concurrency int) ([]dataset.Module, error) {
	// Create a copy to avoid modifying the original
	result := make([]dataset.Module, len(modules))
	copy(result, modules)

	// Create a semaphore to limit concurrent requests
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Track errors
	errors := make([]error, 0)
	var errorsMutex sync.Mutex

	for i := range result {
		// Skip modules that already have data or are invalid
		if result[i].URL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore when done

			module := &result[index]

			// Extract owner/repo from GitHub URL
			owner, repo, err := parseGitHubURL(module.URL)
			if err != nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Errorf("error parsing URL for %s: %w", module.URL, err))
				errorsMutex.Unlock()
				return
			}

			// Get latest commit
			commit, err := getLatestCommit(owner, repo)
			if err != nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Errorf("error getting latest commit for %s: %w", module.URL, err))
				errorsMutex.Unlock()
				return
			}

			// Set the latest tag to the commit hash
			module.Commit = commit

			// Get Go version for this commit
			goVersion, err := getGoVersion(owner, repo, commit)
			if err != nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Errorf("error getting Go version for %s@%s: %w", module.URL, commit, err))
				errorsMutex.Unlock()
				return
			}

			// Set the Go version
			module.GoVersion = goVersion
		}(i)
	}

	wg.Wait()

	// Report errors
	if len(errors) > 0 {
		// Just return the first error for simplicity
		// You could aggregate them if needed
		fmt.Fprintf(os.Stderr, "encountered %d errors during augmentation\n", len(errors))
		for i, err := range errors[:min(5, len(errors))] {
			fmt.Fprintf(os.Stderr, "error %d: %v\n", i+1, err)
		}
		if len(errors) > 5 {
			fmt.Fprintf(os.Stderr, "...and %d more errors\n", len(errors)-5)
		}
	}

	return result, nil
}

// min is a helper to get minimum of two values
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseGitHubURL extracts owner and repo from a GitHub URL
func parseGitHubURL(url string) (string, string, error) {
	// Handle different GitHub URL formats
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	// Extract the path part of the URL
	parts := strings.Split(url, "github.com/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("not a GitHub URL: %s", url)
	}

	// Split path into owner/repo
	pathParts := strings.Split(parts[1], "/")
	if len(pathParts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL format: %s", url)
	}

	return pathParts[0], pathParts[1], nil
}

// getLatestCommit retrieves the latest commit hash for a GitHub repository
func getLatestCommit(owner, repo string) (string, error) {
	// Build API URL for commits
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits", owner, repo)

	// Make request
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("User-Agent", "ASSERT-KTH/go-cryptoapi")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Add("Authorization", "token "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// Parse response
	body, _ := io.ReadAll(resp.Body)
	var commits []struct {
		SHA string `json:"sha"`
	}

	if err := json.Unmarshal(body, &commits); err != nil {
		return "", err
	}

	if len(commits) == 0 {
		return "", fmt.Errorf("no commits found")
	}

	// Return the first commit (newest)
	return commits[0].SHA, nil
}

// getGoVersion extracts Go version from go.mod file at a specific commit
func getGoVersion(owner, repo, commit string) (string, error) {
	// Build API URL for go.mod file
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/go.mod?ref=%s", owner, repo, commit)

	// Make request
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("User-Agent", "Go-RepoInfoTool")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Add("Authorization", "token "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle case where go.mod doesn't exist
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// Parse response
	body, _ := io.ReadAll(resp.Body)
	var content struct {
		Content string `json:"content"`
	}

	if err := json.Unmarshal(body, &content); err != nil {
		return "", err
	}

	// Decode base64 content
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	if err != nil {
		return "", err
	}

	// Extract Go version with regex
	re := regexp.MustCompile(`go\s+([\d.]+)`)
	matches := re.FindStringSubmatch(string(decoded))
	if len(matches) >= 2 {
		return matches[1], nil
	}

	return "", nil
}
