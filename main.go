package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

type value struct {
	two   int16
	four  int32
	eight int64
	char  byte
}

var kernel32 = windows.NewLazyDLL("kernel32.dll")
var OpenProcess = kernel32.NewProc("OpenProcess")
var ReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
var PROCESS_ALL_ACCESS uintptr = 0x1F0FFF

func ReadMemoryWithOffsets(pid uint32, readType string, dataToBeFound int) {
	if readType != "int64" && readType != "int32" && readType != "int16" && readType != "byte" {
		fmt.Printf("Available types are int64, int32, int16 and byte.")
		return
	}
	var k, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if k == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(k))
	var data value
	var addr uintptr = 0
	var mem windows.MemoryBasicInformation
	var offsetValue uintptr
	var readBytes uint
	if readType == "int64" {
		offsetValue = unsafe.Sizeof(data.eight)
	} else if readType == "int32" {
		offsetValue = unsafe.Sizeof(data.four)
	} else if readType == "int16" {
		offsetValue = unsafe.Sizeof(data.two)
	} else if readType == "byte" {
		offsetValue = unsafe.Sizeof(data.char)
	}
	var VirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
	for {
		var m, _, _ = VirtualQueryEx.Call(k, addr, uintptr(unsafe.Pointer(&mem)), unsafe.Sizeof(mem))
		if m == 0 {
			break
		}
		if (mem.Protect == windows.PAGE_EXECUTE_READ || mem.Protect == windows.PAGE_EXECUTE_READWRITE || mem.Protect == windows.PAGE_READWRITE || mem.Protect == windows.PAGE_READONLY) && mem.RegionSize != 0 && mem.State == windows.MEM_COMMIT {
			for offset := uintptr(0); offset < mem.RegionSize; offset += offsetValue {
				var currentAddr = mem.BaseAddress + offset
				if readType == "int64" {
					var a, _, err2 = ReadProcessMemory.Call(k, currentAddr, uintptr(unsafe.Pointer(&data.eight)), unsafe.Sizeof(data.eight), uintptr(unsafe.Pointer(&readBytes)))
					if a == 0 {
						fmt.Printf("[-] ReadProcessMemory error: %s", err2)
						return
					}
					if readBytes > 0 && data.eight == int64(dataToBeFound) {
						fmt.Printf("[+] Read %d bytes from 0x%x value: %d\n", readBytes, currentAddr, data.eight)
					}
				} else if readType == "int32" {
					var a, _, err2 = ReadProcessMemory.Call(k, currentAddr, uintptr(unsafe.Pointer(&data.four)), unsafe.Sizeof(data.four), uintptr(unsafe.Pointer(&readBytes)))
					if a == 0 {
						fmt.Printf("[-] ReadProcessMemory error: %s", err2)
						return
					}
					if readBytes > 0 && data.four == int32(dataToBeFound) {
						fmt.Printf("[+] Read %d bytes from 0x%x value: %d\n", readBytes, currentAddr, data.four)
					}
				} else if readType == "int16" {
					var a, _, err2 = ReadProcessMemory.Call(k, currentAddr, uintptr(unsafe.Pointer(&data.two)), unsafe.Sizeof(data.two), uintptr(unsafe.Pointer(&readBytes)))
					if a == 0 {
						fmt.Printf("[-] ReadProcessMemory error: %s", err2)
						return
					}
					if readBytes > 0 && data.two == int16(dataToBeFound) {
						fmt.Printf("[+] Read %d bytes from 0x%x value: %d\n", readBytes, currentAddr, data.two)
					}
				} else if readType == "byte" {
					var f, _, err2 = ReadProcessMemory.Call(k, currentAddr, uintptr(unsafe.Pointer(&data.char)), unsafe.Sizeof(data.char), uintptr(unsafe.Pointer(&readBytes)))
					if f == 0 {
						fmt.Printf("[-] ReadProcessMemory error: %s", err2)
						return
					}
					if readBytes > 0 && data.char == byte(dataToBeFound) {
						fmt.Printf("[+] Read %d bytes from 0x%x value: %d\n", readBytes, currentAddr, data.char)
					}
				}
			}
		}
		addr = mem.BaseAddress + mem.RegionSize
	}
}

func WriteSpecificMemory(pid uint32, addr uintptr, dataType string, data int) {
	if dataType != "int64" && dataType != "int32" && dataType != "int16" && dataType != "byte" {
		fmt.Println("Available types are int64, int32, int16 and byte.")
		return
	}
	var WriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	var a, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if a == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(a))
	var bytes uint
	if dataType == "int64" {
		var w, _, err1 = WriteProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data)), 8, uintptr(unsafe.Pointer(&bytes)))
		if w == 0 {
			fmt.Printf("[-] WriteProcessMemory error: %s", err1)
			return
		}
		fmt.Printf("[+] %d bytes written. New value is %d", bytes, data)
	} else if dataType == "int32" {
		var w, _, err1 = WriteProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data)), 4, uintptr(unsafe.Pointer(&bytes)))
		if w == 0 {
			fmt.Printf("[-] WriteProcessMemory error: %s", err1)
			return
		}
		fmt.Printf("[+] %d bytes written. New value is %d", bytes, int32(data))
	} else if dataType == "int16" {
		var w, _, err1 = WriteProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data)), 2, uintptr(unsafe.Pointer(&bytes)))
		if w == 0 {
			fmt.Printf("[-] WriteProcessMemory error: %s", err1)
			return
		}
		fmt.Printf("[+] %d bytes written. New value is %d", bytes, int16(data))
	} else if dataType == "byte" {
		var w, _, err1 = WriteProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data)), 1, uintptr(unsafe.Pointer(&bytes)))
		if w == 0 {
			fmt.Printf("[-] WriteProcessMemory error: %s", err1)
			return
		}
		fmt.Printf("[-] WriteProcessMemory error: %s", err1)
	}
}

func ReadSpecificMemory(pid uint32, addr uintptr, readType string) {
	if readType != "int64" && readType != "int32" && readType != "byte" && readType != "int16" {
		fmt.Println("Available types are: int64,int32,int16 and byte.")
		return
	}
	var a, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if a == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(a))
	var data value
	var bytesRead uint
	if readType == "int64" {
		var b, _, err1 = ReadProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data.eight)), unsafe.Sizeof(data.eight), uintptr(unsafe.Pointer(&bytesRead)))
		if b == 0 {
			fmt.Printf("[-] ReadProcessMemory error: %s", err1)
			return
		}
		if bytesRead > 0 {
			fmt.Printf("Address 0x%x\nBytes Read: %d\nValue: %v\n", addr, bytesRead, data.eight)
		}
	} else if readType == "int32" {
		var b, _, err1 = ReadProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data.four)), unsafe.Sizeof(data.four), uintptr(unsafe.Pointer(&bytesRead)))
		if b == 0 {
			fmt.Printf("[-] ReadProcessMemory error: %s", err1)
			return
		}
		if bytesRead > 0 {
			fmt.Printf("Address 0x%x\nBytes Read: %d\nValue: %v\n", addr, bytesRead, data.four)
		}
	} else if readType == "int16" {
		var k, _, err1 = ReadProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data.two)), unsafe.Sizeof(data.two), uintptr(unsafe.Pointer(&bytesRead)))
		if k == 0 {
			fmt.Printf("[-] ReadProcessMemory error: %s", err1)
			return
		}
		if bytesRead > 0 {
			fmt.Printf("Address 0x%x\nBytes Read: %d\nValue: %v\n", addr, bytesRead, data.two)
		}
	} else if readType == "byte" {
		var d, _, err1 = ReadProcessMemory.Call(a, addr, uintptr(unsafe.Pointer(&data.char)), unsafe.Sizeof(data.char), uintptr(unsafe.Pointer(&bytesRead)))
		if d == 0 {
			fmt.Printf("[-] ReadProcessMemory error: %s", err1)
			return
		}
		if bytesRead > 0 {
			fmt.Printf("Address 0x%x\nBytes Read: %d\nValue: %v\n", addr, bytesRead, data.two)
		}
	}

}

func ReadMemory(pid uint32, readType string) {
	if readType != "int64" && readType != "int32" && readType != "int16" && readType != "byte" {
		fmt.Println("Available types are int64,int32,int16 and byte.")
		return
	}
	var v, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if v == 0 {
		fmt.Printf("[-] OpenProcess error: %s", err)
		return
	}
	defer windows.CloseHandle(windows.Handle(v))
	var VirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
	var mem windows.MemoryBasicInformation
	var addr uintptr = 0
	var data value
	var bytesRead uint
	for {
		var a, _, _ = VirtualQueryEx.Call(v, addr, uintptr(unsafe.Pointer(&mem)), unsafe.Sizeof(mem))
		if a == 0 {
			break
		}
		if (mem.Protect == windows.PAGE_EXECUTE_READ || mem.Protect == windows.PAGE_EXECUTE_READWRITE || mem.Protect == windows.PAGE_READWRITE || mem.Protect == windows.PAGE_READONLY) && mem.RegionSize != 0 && mem.State == windows.MEM_COMMIT {
			if readType == "int64" {
				var c, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data.eight)), unsafe.Sizeof(data.eight), uintptr(unsafe.Pointer(&bytesRead)))
				if c == 0 {
					fmt.Printf("[-] ReadProcessMemory error %s", err1)
					return
				}
				if bytesRead > 0 {
					fmt.Printf("[+] Read %d bytes from 0x%x data: %d\n", bytesRead, mem.BaseAddress, data.eight)
				}
			} else if readType == "int32" {
				var l, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data.four)), unsafe.Sizeof(data.four), uintptr(unsafe.Pointer(&bytesRead)))
				if l == 0 {
					fmt.Printf("[-] ReadProcessMemory error %s", err1)
					return
				}
				if bytesRead > 0 {
					fmt.Printf("[+] Read %d bytes from 0x%x data: %d\n", bytesRead, mem.BaseAddress, data.four)
				}
			} else if readType == "int16" {
				var m, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data.two)), unsafe.Sizeof(data.two), uintptr(unsafe.Pointer(&bytesRead)))
				if m == 0 {
					fmt.Printf("[-] ReadProcessMemory error %s", err1)
					return
				}
				if bytesRead > 0 {
					fmt.Printf("[+] Read %d bytes from 0x%x data: %d\n", bytesRead, mem.BaseAddress, data.two)
				}
			} else if readType == "byte" {
				var o, _, err1 = ReadProcessMemory.Call(v, mem.BaseAddress, uintptr(unsafe.Pointer(&data.char)), unsafe.Sizeof(data.char), uintptr(unsafe.Pointer(&bytesRead)))
				if o == 0 {
					fmt.Printf("[-] ReadProcessMemory error %s", err1)
					return
				}
				if bytesRead > 0 {
					fmt.Printf("[+] Read %d bytes from 0x%x data: %d\n", bytesRead, mem.BaseAddress, data.char)
				}
			}
		}
		addr = mem.BaseAddress + mem.RegionSize
	}
}

func main() {
	var proc windows.ProcessEntry32
	var processName string
	fmt.Println("Enter process name you want to scan:")
	fmt.Scanf("%s\n", &processName)
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
	var choice int
	fmt.Printf("Available operations are:\n1\tScan/read memory base addresses.\n2\tSearch memory for a specific value.\n3\tRead a value at specific memory address.\n4\tWrite a new value to a specific memory address.\nEnter your choice: (1,2,3,4)\n")
	fmt.Scanf("%d\n", &choice)
	switch choice {
	case 1:
		var t string
		fmt.Println("Enter a data type to scan: (int64,int32,int16 and byte)")
		fmt.Scanf("%s\n", &t)
		ReadMemory(proc.ProcessID, t)
	case 2:
		var t string
		var val int
		fmt.Println("Enter a data type to scan: (int64,int32,int16 and byte)")
		fmt.Scanf("%s\n", &t)
		fmt.Println("Enter a value to search:")
		fmt.Scanf("%d\n", &val)
		ReadMemoryWithOffsets(proc.ProcessID, t, val)
	case 3:
		var addr uintptr
		var t string
		fmt.Println("Enter an address to scan: (Example: 0xd16c3ff8bc)")
		fmt.Scanf("%v\n", &addr)
		fmt.Println("Enter a data type to scan: (int64,int32,int16 and byte)")
		fmt.Scanf("%s\n", &t)
		ReadSpecificMemory(proc.ProcessID, addr, t)
	case 4:
		var addr uintptr
		var t string
		var val int
		fmt.Println("Enter an address to write: (Example: 0x98ac7ffc4c) ")
		fmt.Scanf("%v\n", &addr)
		fmt.Println("Enter a data type to write: (int64,int32,int16 and byte)")
		fmt.Scanf("%s\n", &t)
		fmt.Println("Enter a data to write:")
		fmt.Scanf("%d\n", &val)
		WriteSpecificMemory(proc.ProcessID, addr, t, val)
	default:
		fmt.Printf("Enter a valid operation.\n")
	}
}
