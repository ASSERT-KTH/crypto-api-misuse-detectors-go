package analyzer

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/utils"
	"golang.org/x/sync/semaphore"
)

// Defines settings for the Gopher tool execution
type GopherConfig struct {
	ToolPath   string
	Timeout    time.Duration
	MaxThreads int
}

// Execution logic
type GopherRunner struct {
	Config    GopherConfig
	Sem       *semaphore.Weighted // Non-blocking
	RepoLocks sync.Map            // Maps RepoPath -> *sync.Mutex Map (safe for concurrent use)
	//Logs      map[int][]LogEntry // needs a store log function
}

// Implements the Stringer interface for GopherConfig
func (gc GopherConfig) String() string {
	return fmt.Sprintf("GopherConfig{ToolPath: %s, Timeout: %s, MaxThreads: %d}", gc.ToolPath, gc.Timeout, gc.MaxThreads)
}

// Implements the Stringer interface for GopherRunner
func (gr GopherRunner) String() string {
	return fmt.Sprintf("GopherRunner{Config: %s, MaxThreads: %d}", gr.Config.String(), gr.Config.MaxThreads)
}

// // Captures execution logs per vulnerability package
// type LogEntry struct {
// 	Package string
// 	GitTag  string
// 	Stdout  string
// 	Stderr  string
// 	Error   error
// }

// TODO extra implement a queue for locked repos
func (gr *GopherRunner) Run(repo *Repo, gitTag string) {
	//create and acquire lock, defer it
	//ctx := context.Background()
	repoLock := gr.getRepoLock(repo.RepoPath)
	repoLock.Lock() // blocking, TODO smarter queue
	defer repoLock.Unlock()

	for {
		if acquired := gr.Sem.TryAcquire(1); acquired == true {
			break
		}
		time.Sleep(time.Duration(10 * time.Second))
	}

	defer gr.Sem.Release(1)
	// checkout
	if err := repo.Checkout(gitTag); err != nil {
		log.Printf("Failed to checkout %s at %s: %v\n", repo.RepoSlug, gitTag, err)
		return
	}
	log.Printf("Running Gopher tool on %s at %s with config %+v\n", repo.RepoPath, gitTag, gr.Config)
	if err := gr.invokeGopher(repo.RepoPath); err != nil {
		log.Printf("Gopher tool failed for %s: %v", repo.RepoPath, err)
	}
	return
}

func (gr *GopherRunner) getRepoLock(repoPath string) *sync.Mutex {
	lock, _ := gr.RepoLocks.LoadOrStore(repoPath, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// invokeGopher now belongs to GopherRunner
func (gr *GopherRunner) invokeGopher(repoPath string) error {
	toolPath := gr.Config.ToolPath // get tool path from config

	return utils.RunCommandWithTimeout(repoPath, toolPath, []string{"."}, gr.Config.Timeout)

	// if err := utils.RunCommandWithTimeout(repoPath, toolPath, []string{"."}, gr.Config.Timeout); err != nil {
	// 	log.Printf("Failed to run Gopher in %s: %v", repoPath, err)

	// 	// if failed, try a child directory
	// 	childDir, err := utils.FindChildDir(repoPath)
	// 	if err != nil {
	// 		log.Printf("No valid child directories found in %s", repoPath)
	// 		return err
	// 	}

	// 	log.Printf("Retrying in child directory: %s", childDir)
	// 	return utils.RunCommandWithTimeout(childDir, toolPath, []string{"."}, gr.Config.Timeout)
	// }

	return nil
}
