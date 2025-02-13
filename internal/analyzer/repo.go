package analyzer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Represents a (local) repository that contains potentially vulnerable packages.
type Repo struct {
	RepoSlug string   `json:"repo_slug"`
	RepoPath string   `json:"repo_path"`
	GitTags  []string `json:"git_tags"`
}


func (r Repo) String() string {
	return fmt.Sprintf("Repo:\n\tRepoSlug: %s\n\tRepoPath: %s", r.RepoSlug, r.RepoPath)
}

// TODO where do i use this?
func (r *Repo) Exists() bool {
	_, err := os.Stat(r.RepoPath)
	return err == nil
}

// Checks out the repo at given tag with timeout
func (r *Repo) Checkout(gitTag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "checkout", gitTag)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error downloading repository: %w, output: %s", err, output)
	}
	return err
}


// func (r *Repo) Lock() (f.file, error) {
// }
