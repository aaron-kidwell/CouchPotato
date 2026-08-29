#include <Windows.h>
#pragma function(memcpy)
#pragma function(memset)
#pragma function(memcmp)
#pragma function(strlen)
#pragma function(strcpy)
#pragma function(strcat)
#pragma function(strncpy)
#pragma function(strcmp)

ULONG_PTR __security_cookie = 0xBB40E64E;
ULONG_PTR __security_cookie_complement = ~((ULONG_PTR)0xBB40E64E);
void __cdecl __security_check_cookie(ULONG_PTR c) { (void)c; }
void __cdecl __GSHandlerCheck(void) {}
void __cdecl __chkstk(void) {}
void __cdecl __report_rangecheckfailure(void) { ExitProcess(1); }

void* __cdecl memcpy(void* d, const void* s, size_t n) {
    char* dd = (char*)d;
    const char* ss = (const char*)s;
    while (n--) *dd++ = *ss++;
    return d;
}
void* __cdecl memset(void* d, int v, size_t n) {
    char* dd = (char*)d;
    while (n--) *dd++ = (char)v;
    return d;
}
int __cdecl memcmp(const void* a, const void* b, size_t n) {
    return (RtlCompareMemory(a, b, n) == n) ? 0 : 1;
}

size_t __cdecl strlen(const char* s) { return (size_t)lstrlenA(s); }
int    __cdecl strcmp(const char* a, const char* b) { return lstrcmpA(a, b); }
char* __cdecl strcpy(char* d, const char* s) { lstrcpyA(d, s); return d; }
char* __cdecl strcat(char* d, const char* s) { lstrcatA(d, s); return d; }

char* __cdecl strchr(const char* s, int c) {
    while (*s) { if (*s == (char)c) return (char*)s; s++; }
    return (c == 0) ? (char*)s : NULL;
}
char* __cdecl strncpy(char* d, const char* s, size_t n) {
    size_t i = 0;
    while (i < n && s[i]) { d[i] = s[i]; i++; }
    while (i < n) d[i++] = 0;
    return d;
}

extern int main(void);
void __cdecl mainCRTStartup(void) { ExitProcess(main()); }