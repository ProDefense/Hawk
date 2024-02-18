package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"strings"
	"time"
	"golang.org/x/sys/unix"
)

var shutdownChan = make(chan struct{})

func main() {
	fmt.Println("Tracer program starting...")
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		close(shutdownChan)
		os.Exit(0)
	}()
	watchSSHDProcesses()
}

func watchSSHDProcesses() {
	for {
		select {
		case <-shutdownChan:
			fmt.Println("Received shutdown signal. Exiting...")
			return
		default:
			fmt.Println("Checking for SSHD processes...")
			sshdPIDs, err := findSSHDProcesses()
			if err != nil {
				fmt.Printf("Error finding SSHD processes: %v\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for _, pid := range sshdPIDs {
				go traceSSHDProcess(pid)
			}

			time.Sleep(5 * time.Second) 
		}
	}
}

func findSSHDProcesses() ([]int, error) {
	var sshdPIDs []int
	dir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}
		if isSSHDProcess(pid) {
			sshdPIDs = append(sshdPIDs, pid)
		}
	}

	return sshdPIDs, nil
}

func isSSHDProcess(pid int) bool {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false
	}
	words := strings.FieldsFunc(string(cmdline), func(r rune) bool {
	return r == ' ' || r == 0
	})
	if len(words) > 0 && strings.HasPrefix(words[0], "sshd") {
		return true
	}

	return false
}

func traceSSHDProcess(pid int) {
	fmt.Printf("Tracing SSHD process with PID: %d\n", pid)
	err := attachToProcess(pid)
	if err != nil {
		fmt.Printf("Error attaching to process %d: %v\n", pid, err)
		return
	}
	defer detachFromProcess(pid)
	traceSyscalls(pid)
}

func attachToProcess(pid int) error {
	pidStr := strconv.Itoa(pid)

	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("error attaching to process %s: %v", pidStr, err)
	}

	var status syscall.WaitStatus
	_, err := syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return fmt.Errorf("error waiting for process %s: %v", pidStr, err)
	}

	fmt.Printf("Attached to process %s\n", pidStr)
	return nil
}

func detachFromProcess(pid int) {
	pidStr := strconv.Itoa(pid)

	unix.PtraceDetach(pid)
	fmt.Printf("Detached from process %s\n", pidStr)
}

func traceSyscalls(pid int) {
	pidStr := strconv.Itoa(pid)

	for {
		select {
		case <-shutdownChan:
			fmt.Printf("Received shutdown signal. Detaching from process %s and exiting...\n", pidStr)
			unix.PtraceDetach(pid)
			return
		default:
			fmt.Printf("Waiting for process %s\n", pidStr)
			var status syscall.WaitStatus
			_, err := syscall.Wait4(pid, &status, 0, nil)
			if err != nil {
				fmt.Printf("Error waiting for process %s: %v\n", pidStr, err)
				return
			}

			fmt.Printf("Status for process %s: %+v\n", pidStr, status)

			if status.Exited() {
				fmt.Printf("Process %s has exited\n", pidStr)
				return
			}

			if status.StopSignal() == syscall.SIGTRAP {
				fmt.Println("Syscall traced")

				err = unix.PtraceSyscall(pid, 0)
				if err != nil {
					fmt.Printf("Error continuing process %s: %v\n", pidStr, err)
					return
				}

				err = unix.PtraceCont(pid, 0)
				if err != nil {
					fmt.Printf("Error resuming process %s: %v\n", pidStr, err)
					return
				}
			}
		}
	}
}