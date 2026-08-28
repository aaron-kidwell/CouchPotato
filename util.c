#include <Windows.h>
#include <stdarg.h>
#include "util.h"


static int sf_itoa(char* buf, unsigned long long v, int base, int upper) {
    const char* dig = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[24]; int i = 0;
    if (v == 0) { buf[0] = '0'; buf[1] = 0; return 1; }
    while (v) { tmp[i++] = dig[v % base]; v /= base; }
    for (int j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
    buf[i] = 0;
    return i;
}

static int sf_format(char* out, size_t sz, const char* fmt, va_list ap) {
    char* p = out; char* end = out + sz - 1;
    while (*fmt && p < end) {
        if (*fmt != '%') { *p++ = *fmt++; continue; }
        fmt++;
        switch (*fmt++) {
        case 's': {
            const char* s = va_arg(ap, const char*);
            if (!s) s = "(null)";
            while (*s && p < end) *p++ = *s++;
            break;
        }
        case 'd': case 'i': {
            int v = va_arg(ap, int); char tmp[16];
            if (v < 0) { if (p < end) *p++ = '-'; v = -v; }
            sf_itoa(tmp, (unsigned)v, 10, 0);
            for (char* t = tmp; *t && p < end; t++) *p++ = *t;
            break;
        }
        case 'u': {
            unsigned v = va_arg(ap, unsigned); char tmp[16];
            sf_itoa(tmp, v, 10, 0);
            for (char* t = tmp; *t && p < end; t++) *p++ = *t;
            break;
        }
        case 'l':
            if (*fmt == 'u' || *fmt == 'd') {
                int sgn = (*fmt == 'd'); fmt++;
                unsigned long v = va_arg(ap, unsigned long); char tmp[16];
                if (sgn && (long)v < 0) { if (p < end) *p++ = '-'; v = (unsigned long)(-(long)v); }
                sf_itoa(tmp, v, 10, 0);
                for (char* t = tmp; *t && p < end; t++) *p++ = *t;
            }
            break;
        case 'p': case 'X': case 'x': {
            unsigned long long v = va_arg(ap, unsigned long long); char tmp[20];
            sf_itoa(tmp, v, 16, *(fmt - 1) == 'X');
            for (char* t = tmp; *t && p < end; t++) *p++ = *t;
            break;
        }
        case '%': if (p < end) *p++ = '%'; break;
        default:  if (p < end) *p++ = '?'; break;
        }
    }
    *p = 0;
    return (int)(p - out);
}

// Print to stdout
void con_printf(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    sf_format(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    DWORD written;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE)
        WriteFile(hOut, buf, lstrlenA(buf), &written, NULL);
}