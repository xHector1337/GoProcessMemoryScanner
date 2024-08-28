package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

var kernel32 = windows.NewLazyDLL("kernel32.dll")

func ReadMemory(pid uint32) {
	var OpenProcess = kernel32.NewProc("OpenProcess")
	var v, _, err = OpenProcess.Call(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, uintptr(pid))
	if v == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(v))
	var VirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
	var ReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	var mem windows.MemoryBasicInformation
	var addr uintptr = 0
	for {
		var data = make([]byte, 4096)
		var bytesRead uintptr
		var a, _, _ = VirtualQueryEx.Call(v, addr, uintptr(unsafe.Pointer(&mem)), unsafe.Sizeof(mem))
		if a == 0 {
			break
		}
		if mem.State == windows.MEM_COMMIT {
			var m, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data[0])), unsafe.Sizeof(data), bytesRead)
			if m == 0 {
				fmt.Printf("[-] ReadProcessMemory error: %s", err1)
				return
			}
			fmt.Printf("\nBase Address: 0x%x Value: %v\n", mem.BaseAddress, data)
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
		}
	}
	fmt.Printf("[+] Process Name: %s\n[+] Process id: %d\n", windows.UTF16ToString(proc.ExeFile[:]), proc.ProcessID)
	ReadMemory(proc.ProcessID)

}
