package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

var kernel32 = windows.NewLazyDLL("kernel32.dll")
var OpenProcess = kernel32.NewProc("OpenProcess")
var ReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
var PROCESS_ALL_ACCESS uintptr = 0x1F0FFF

func ReadMemory(pid uint32) {
	var v, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if v == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(v))
	var VirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
	var mem windows.MemoryBasicInformation
	var addr uintptr = 0
	var data int
	var bytesRead uint32
	for {
		var a, _, _ = VirtualQueryEx.Call(v, addr, uintptr(unsafe.Pointer(&mem)), unsafe.Sizeof(mem))
		if a == 0 {
			break
		}
		if (mem.Protect == windows.PAGE_EXECUTE_READ || mem.Protect == windows.PAGE_EXECUTE_READWRITE || mem.Protect == windows.PAGE_READWRITE || mem.Protect == windows.PAGE_READONLY) && mem.RegionSize != 0 {
			var c, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Sizeof(data)), uintptr(unsafe.Pointer(&bytesRead)))
			if c == 0 {
				fmt.Printf("[-] ReadProcessMemory error %s", err1)
				return
			}
			if bytesRead > 0 {
				fmt.Printf("[+] Read %d bytes from 0x%x data: %d\n", bytesRead, mem.BaseAddress, data)
			}
		}

		addr = mem.BaseAddress + mem.RegionSize
	}
}

func main() {
	var proc windows.ProcessEntry32
	var processName string = "a.exe"
	//fmt.Scanf("%s\n", processName)
	proc.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
	var CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	var v, _, err = CreateToolhelp32Snapshot.Call(windows.TH32CS_SNAPALL, 0)
	if v == uintptr(windows.InvalidHandle) {
		fmt.Printf("[-] CreateToolhelp32Snapshot error: %s", err)
		return
	}
	var Process32First = kernel32.NewProc("Process32FirstW")
	var b, _, err1 = Process32First.Call(v, uintptr(unsafe.Pointer(&proc)))
	if b == 0 {
		fmt.Printf("[-] Process32FirstW error: %s", err1)
		return
	}
	var Process32Next = kernel32.NewProc("Process32NextW")
	for strings.ToUpper(windows.UTF16ToString(proc.ExeFile[:])) != strings.ToUpper(processName) {
		var c, _, err2 = Process32Next.Call(v, uintptr(unsafe.Pointer(&proc)))
		if c == 0 {
			fmt.Printf("[-] Process32NextW error: %s", err2)
			return
		}
	}
	fmt.Printf("[+] Process Name: %s\n[+] Process id: %d\n", windows.UTF16ToString(proc.ExeFile[:]), proc.ProcessID)
	ReadMemory(proc.ProcessID)

}
