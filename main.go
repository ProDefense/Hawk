package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
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
