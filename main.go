package main

import (
	"os"
	"os/signal"
	"syscall"
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
	watchSSHDProcesses()
}
