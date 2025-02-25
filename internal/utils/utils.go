package utils

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// RunCommandWithTimeout runs command in dir with a timeout context
func RunCommandWithTimeout(dir, command string, args []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	cmdString := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	log.Printf("Running command `%s` in directory: %s", cmdString, dir)

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = dir

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Format output for readability - split into lines for multiline output
		formattedOutput := formatCommandOutput(output)
		
		// Check for context timeout
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("COMMAND TIMEOUT ERROR:\n"+
				"Command: %s\n"+
				"Directory: %s\n"+
				"Timeout: %s\n"+
				"Output:\n%s", 
				cmdString, dir, timeout, formattedOutput)
			return fmt.Errorf("command timed out after %s", timeout)
		}
		
		// Format error message based on error type
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("COMMAND EXECUTION ERROR:\n"+
				"Command: %s\n"+
				"Directory: %s\n"+
				"Exit Code: %d\n"+
				"Output:\n%s", 
				cmdString, dir, exitErr.ExitCode(), formattedOutput)
		} else {
			log.Printf("COMMAND ERROR:\n"+
				"Command: %s\n"+
				"Directory: %s\n"+
				"Error: %v\n"+
				"Output:\n%s", 
				cmdString, dir, err, formattedOutput)
		}
		
		return fmt.Errorf("command failed: %w", err)
	}

	log.Printf("Command `%s` executed successfully.", cmdString)
	if len(output) > 0 {
		log.Printf("Command output:\n%s", formatCommandOutput(output))
	}
	
	return nil
}

// formatCommandOutput formats command output for better readability in logs
func formatCommandOutput(output []byte) string {
	if len(output) == 0 {
		return "<no output>"
	}
	
	// Trim trailing whitespace
	outputStr := strings.TrimSpace(string(output))
	
	// If output contains multiple lines, indent each line for better readability
	if strings.Contains(outputStr, "\n") {
		lines := strings.Split(outputStr, "\n")
		for i, line := range lines {
			lines[i] = "    " + line
		}
		return strings.Join(lines, "\n")
	}
	
	return outputStr
}