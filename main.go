package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

var kernel32 = windows.NewLazyDLL("kernel32.dll")

func ReadMemory(pid uint) {
	var OpenProcess = kernel32.NewProc("OpenProcess")
	var v, _, err = OpenProcess.Call(windows.PROCESS_VM_READ, 0, uintptr(pid))
	if v == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(v))
}

func main() {
	var proc windows.ProcessEntry32
	var processName string = "Spotify.exe"
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
	for windows.UTF16ToString(proc.ExeFile[:]) != processName {
		var c, _, err2 = Process32Next.Call(v, uintptr(unsafe.Pointer(&proc)))
		if c == 0 {
			fmt.Printf("[-] Process32NextW error: %s", err2)
		}
	}
	fmt.Printf("[+] Process Name: %s\n[+] Process id: %d\n", windows.UTF16ToString(proc.ExeFile[:]), proc.ProcessID)

}
