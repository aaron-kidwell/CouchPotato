#pragma once
#include <Windows.h>

void con_printf(const char* fmt, ...);
BOOL EtwPatch();
extern DWORD g_ssn;
extern PVOID g_syscall;
NTSTATUS iNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
DWORD getSSN(char* funcName);
PVOID getSyscallAddr(char* funcName);
PVOID manual_procaddress(HMODULE mod_handle, const char* funcName);

