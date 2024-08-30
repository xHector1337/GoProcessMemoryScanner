# Introduction and Features

It is a project that I made to learn more about Windows Internals. You can also imagine it as CLI Basic Cheat Engine.
It can get base memory addresses of a process, search through a value in process's memory, read value at a specific memory address and write to a specific memory address.
It uses VirtualQueryEx, OpenProcess, ReadProcessMemory, WriteProcessMemory, CreateToolhelp32Snapshot, Process32FirstW and Process32NextW.

# Building Memory Scanner

After cloning the repository you can build it by using `go build .\main.go`.
Then run `main.exe`.

# Building Example Program

It is an example program that I made to test my memory scanner. You can simply build it by using `gcc example.c`.

# Disclaimer

I made it for educational reasons, don't use it for illegal purposes!
