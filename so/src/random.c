#include "mh1721_internal.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef BOOLEAN (WINAPI *mh_rtlgenrandom_fn)(PVOID, ULONG);

int mh_random(uint8_t *buf, int len) {
    HMODULE lib;
    mh_rtlgenrandom_fn fn;
    if (!buf || len <= 0) {
        return -1;
    }
    lib = LoadLibraryA("advapi32.dll");
    if (!lib) {
        return -1;
    }
    fn = (mh_rtlgenrandom_fn)GetProcAddress(lib, "SystemFunction036");
    if (!fn || !fn(buf, (ULONG)len)) {
        return -1;
    }
    return 0;
}
#else
#include <fcntl.h>
#include <unistd.h>

int mh_random(uint8_t *buf, int len) {
    int fd;
    int off = 0;
    if (!buf || len <= 0) {
        return -1;
    }
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    while (off < len) {
        int n = (int)read(fd, buf + off, (size_t)(len - off));
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += n;
    }
    close(fd);
    return 0;
}
#endif
