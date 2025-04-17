package compose

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// waitForBatchContainers waits for all containers in a batch to complete
func waitForBatchContainers(composeFilePath string, profile string, ctx context.Context) error {
	// Get container IDs for the batch
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFilePath, "--profile", profile, "ps", "-q")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get container IDs: %w", err)
	}

	// If no containers, we're done
	containerIDs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(containerIDs) == 0 || (len(containerIDs) == 1 && containerIDs[0] == "") {
		return nil
	}

	// Wait for each container
	for _, containerID := range containerIDs {
		if containerID == "" {
			continue
		}
		waitCmd := exec.CommandContext(ctx, "docker", "wait", containerID)
		if err := waitCmd.Run(); err != nil {
			// Log error but continue with other containers
			fmt.Printf("Warning: container %s failed: %v\n", containerID, err)
		}
	}

	return nil
}

// runBatch executes a single batch using docker compose
func runBatch(composeFilePath string, batchNum int, ctx context.Context) error {
	profile := fmt.Sprintf("batch%d", batchNum)

	// Start the batch in detached mode
	upCmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFilePath, "--profile", profile, "up", "--build", "--remove-orphans", "-d")
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr

	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("failed to start batch %d: %w", batchNum, err)
	}

	// Wait for containers to complete
	if err := waitForBatchContainers(composeFilePath, profile, ctx); err != nil {
		// Check if it's a timeout
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timeout waiting for batch %d containers: %w", batchNum, err)
		}
		// For other errors, log but continue
		fmt.Printf("Warning: batch %d had container failures: %v\n", batchNum, err)
	}

	return nil
}

// runBatches executes all batches in sequence using docker compose
func runBatches(composeFilePath string, totalBatches int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for batchNum := 1; batchNum <= totalBatches; batchNum++ {
		fmt.Printf("Starting batch %d/%d...\n", batchNum, totalBatches)
		if err := runBatch(composeFilePath, batchNum, ctx); err != nil {
			// Only return error if it's a timeout
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("timeout occurred: %w", err)
			}
			// For other errors, log and continue
			fmt.Printf("Warning: batch %d failed but continuing: %v\n", batchNum, err)
		}
		fmt.Printf("Batch %d completed\n", batchNum)
	}
	return nil
}
