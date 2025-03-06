package analyzer

import (
	"fmt"
	"os"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/utils"
)

// Represents a (local) repository that contains potentially vulnerable packages.
type Repo struct {
	RepoSlug string   `json:"repo_slug"`
	RepoPath string   
	GitTags  []string `json:"git_tags"`
}


func (r Repo) String() string {
	return fmt.Sprintf("Repo:\n\tRepoSlug: %s\n\tRepoPath: %s", r.RepoSlug, r.RepoPath)
}

// Checks out the repo at given tag with timeout
func (r *Repo) Checkout(gitTag string) error {
	utils.RunCommandWithTimeout(r.RepoPath, "git", []string{"checkout", gitTag}, time.Second*12)
	// if err != nil {
	// 	return fmt.Errorf("error checking out repository: %s at `%s`: %w", r.RepoPath, gitTag, err)
	// }
	return nil
}
