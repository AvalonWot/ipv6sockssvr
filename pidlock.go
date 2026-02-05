package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const _pidFile = "/var/run/ipv6sockssvr.pid"

// ensureSingleInstance checks if another instance is running and creates a PID lock file
func ensureSingleInstance() error {
	// Try to read existing PID file
	data, err := os.ReadFile(_pidFile)
	if err == nil {
		// PID file exists, check if process is still running
		pidStr := strings.TrimSpace(string(data))
		if pid, err := strconv.Atoi(pidStr); err == nil {
			// Check if process exists
			process, err := os.FindProcess(pid)
			if err == nil {
				// Try to send signal 0 to check if process is alive
				err := process.Signal(syscall.Signal(0))
				if err == nil {
					return fmt.Errorf("another instance is already running (PID: %d)", pid)
				}
			}
		}
		// Process not running, remove stale PID file
		os.Remove(_pidFile)
	}

	// Create new PID file
	pid := os.Getpid()
	err = os.WriteFile(_pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644)
	if err != nil {
		return fmt.Errorf("failed to create PID file: %v", err)
	}

	return nil
}

// cleanupPidFile removes the PID lock file
func cleanupPidFile() {
	os.Remove(_pidFile)
}
