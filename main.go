package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var outfile = "/dev/null"

func needroot() {
	fmt.Println("You don't have permission to attach to other users' processes.")
	os.Exit(1)
}


func terminal(done chan bool) {
	go plisten()
	for {
		select {
		case <-done:
			return
		case <-time.After(1 * time.Second):
		}
	}
}

func main() {
	signalCh := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(
		signalCh,
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP,
		syscall.SIGPIPE, syscall.SIGTERM, syscall.SIGSEGV,
		syscall.SIGBUS, syscall.SIGILL, syscall.SIGCHLD,
	)

	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM:
				fmt.Printf("Exiting on signal %v.\n", sig)
				close(done)
			}
		}
	}()

	if os.Geteuid() != 0 {
		needroot()
	}

	terminal(done)
}

func plisten() {
	for {
		time.Sleep(1 * time.Second)
		fmt.Println("Checking for process events...")
	}
}
