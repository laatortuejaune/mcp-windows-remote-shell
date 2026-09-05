//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	procThreadAttributeHandleList     = 0x20002
	procThreadAttributeJobList        = 0x2000d
	extendedStartupInfoPresent        = 0x80000
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	createJobObject                = kernel32.NewProc("CreateJobObjectW")
	setInformationJobObject        = kernel32.NewProc("SetInformationJobObject")
	terminateJobObject             = kernel32.NewProc("TerminateJobObject")
	initializeProcThreadAttributes = kernel32.NewProc("InitializeProcThreadAttributeList")
	updateProcThreadAttribute      = kernel32.NewProc("UpdateProcThreadAttribute")
	deleteProcThreadAttributes     = kernel32.NewProc("DeleteProcThreadAttributeList")
	getSystemDirectory             = kernel32.NewProc("GetSystemDirectoryW")
)

// Windows SDK layouts, including pointer-sized SIZE_T fields. Keeping these
// declarations here preserves the agent's stdlib-only dependency policy.
type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IOCounters            [6]uint64
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList unsafe.Pointer
}

// The job-list creation attribute (Windows 10+) associates the shell atomically,
// before it can spawn children. The job handle is never inherited, so an abrupt
// agent exit also kills the job. The raw cmd line avoids Go's argv escaping.
func startCommand(command string, env []string) (_ *runningCommand, err error) {
	pipes, err := newCommandPipes()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			pipes.close()
		}
	}()
	jobValue, _, callErr := createJobObject.Call(0, 0)
	if jobValue == 0 {
		return nil, fmt.Errorf("create command job: %w", callErr)
	}
	job := syscall.Handle(jobValue)
	defer func() {
		if err != nil {
			_ = syscall.CloseHandle(job)
		}
	}()
	limits := jobExtendedLimitInformation{}
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, callErr := setInformationJobObject.Call(uintptr(job), jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return nil, fmt.Errorf("configure command job: %w", callErr)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	inherited := make([]syscall.Handle, 3)
	defer func() {
		for _, handle := range inherited {
			if handle != 0 {
				_ = syscall.CloseHandle(handle)
			}
		}
	}()
	for i, file := range []*os.File{pipes.in, pipes.outW, pipes.errW} {
		if err := syscall.DuplicateHandle(current, syscall.Handle(file.Fd()), current,
			&inherited[i], 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, fmt.Errorf("prepare command handles: %w", err)
		}
	}
	var attributeBytes uintptr
	_, _, callErr = initializeProcThreadAttributes.Call(0, 2, 0, uintptr(unsafe.Pointer(&attributeBytes)))
	if attributeBytes == 0 {
		return nil, fmt.Errorf("size process attributes: %w", callErr)
	}
	attributes := make([]uintptr, (attributeBytes+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	attributeList := unsafe.Pointer(&attributes[0])
	ok, _, callErr = initializeProcThreadAttributes.Call(uintptr(attributeList), 2, 0,
		uintptr(unsafe.Pointer(&attributeBytes)))
	if ok == 0 {
		return nil, fmt.Errorf("initialize process attributes: %w", callErr)
	}
	jobs := []syscall.Handle{job}
	defer func() {
		deleteProcThreadAttributes.Call(uintptr(attributeList))
		runtime.KeepAlive(attributes)
		runtime.KeepAlive(inherited)
		runtime.KeepAlive(jobs)
	}()
	ok, _, callErr = updateProcThreadAttribute.Call(uintptr(attributeList), 0, procThreadAttributeHandleList,
		uintptr(unsafe.Pointer(&inherited[0])), uintptr(len(inherited))*unsafe.Sizeof(inherited[0]), 0, 0)
	if ok == 0 {
		return nil, fmt.Errorf("restrict inherited handles: %w", callErr)
	}
	ok, _, callErr = updateProcThreadAttribute.Call(uintptr(attributeList), 0, procThreadAttributeJobList,
		uintptr(unsafe.Pointer(&jobs[0])), unsafe.Sizeof(jobs[0]), 0, 0)
	if ok == 0 {
		return nil, fmt.Errorf("attach command job at creation (Windows 10 or later required): %w", callErr)
	}
	var directory [32768]uint16
	n, _, callErr := getSystemDirectory.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
	if n == 0 || n >= uintptr(len(directory)) {
		return nil, fmt.Errorf("resolve system command interpreter: %w", callErr)
	}
	app, err := syscall.UTF16PtrFromString(syscall.UTF16ToString(directory[:n]) + `\cmd.exe`)
	if err != nil {
		return nil, err
	}
	line, err := syscall.UTF16PtrFromString("cmd.exe /d /c " + command)
	if err != nil {
		return nil, errors.New("command contains a NUL character")
	}
	environment, err := windowsEnvironmentBlock(env)
	if err != nil {
		return nil, err
	}
	startup := startupInfoEx{AttributeList: attributeList}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = inherited[0], inherited[1], inherited[2]
	var process syscall.ProcessInformation
	if err := syscall.CreateProcess(app, line, nil, nil, true,
		syscall.CREATE_UNICODE_ENVIRONMENT|extendedStartupInfoPresent, &environment[0], nil,
		&startup.StartupInfo, &process); err != nil {
		return nil, fmt.Errorf("start command in job: %w", err)
	}
	_ = syscall.CloseHandle(process.Thread)
	pipes.closeChildEnds()
	return &runningCommand{
		stdout: pipes.outR,
		stderr: pipes.errR,
		wait: func() (int, error) {
			if _, err := syscall.WaitForSingleObject(process.Process, syscall.INFINITE); err != nil {
				return -1, err
			}
			var code uint32
			if err := syscall.GetExitCodeProcess(process.Process, &code); err != nil {
				return -1, err
			}
			if code != 0 {
				return int(code), fmt.Errorf("process exited with status %d", code)
			}
			return 0, nil
		},
		terminate: func() error {
			ok, _, err := terminateJobObject.Call(uintptr(job), 1)
			if ok == 0 {
				_ = syscall.TerminateProcess(process.Process, 1)
				return fmt.Errorf("terminate command job: %w", err)
			}
			return nil
		},
		close: func() error {
			return errors.Join(syscall.CloseHandle(job), syscall.CloseHandle(process.Process))
		},
	}, nil
}

func windowsEnvironmentBlock(env []string) ([]uint16, error) {
	ordered := append([]string(nil), env...)
	for _, item := range ordered {
		if strings.ContainsRune(item, 0) {
			return nil, errors.New("invalid command environment")
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return windowsEnvironmentKey(ordered[i]) < windowsEnvironmentKey(ordered[j]) })
	return utf16.Encode([]rune(strings.Join(ordered, "\x00") + "\x00\x00")), nil
}

func windowsEnvironmentKey(item string) string {
	start := 0
	if strings.HasPrefix(item, "=") {
		start = 1 // Hidden per-drive working directories use names such as =C:.
	}
	if end := strings.IndexByte(item[start:], '='); end >= 0 {
		return strings.ToUpper(item[:start+end])
	}
	return strings.ToUpper(item)
}
