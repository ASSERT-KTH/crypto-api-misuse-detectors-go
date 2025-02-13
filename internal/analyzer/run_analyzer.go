package analyzer

import (
	"sync"
	"time"

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

// // Captures execution logs per vulnerability package
// type LogEntry struct {
// 	Package string
// 	GitTag  string
// 	Stdout  string
// 	Stderr  string
// 	Error   error
// }

// TODO extra implement a queue for locked repos
func (gr *GopherRunner) Run(repo Repo, gitTag string) {

	//create and acquire lock, defer it
	// checkout
	// Execute gopher tool on collected repositories using timeout execution context
	// log
	return
}

func (gr *GopherRunner) GetRepoLock(repoPath string) *sync.Mutex {
	// return a sync mutex
	return nil
}
