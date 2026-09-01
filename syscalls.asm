.code
EXTERN g_ssn:DWORD
EXTERN g_syscall:QWORD

iNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn
    jmp qword ptr [g_syscall]
iNtProtectVirtualMemory ENDP

iNtOpenThreadToken PROC
    mov r10, rcx
    mov eax, g_ssn
    jmp qword ptr [g_syscall]
iNtOpenThreadToken ENDP

iNtDuplicateToken PROC
    mov r10, rcx
    mov eax, g_ssn
    jmp qword ptr [g_syscall]
iNtDuplicateToken ENDP

end