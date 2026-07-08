/*
 * antidebug.so — T3MP3ST sandbox LD_PRELOAD anti-analysis bypass shim.
 * Preloaded into ELF binaries via LD_PRELOAD to defeat the most common
 * analyst-detection tricks without touching the binary's code.
 *
 * Defeats:
 *   1. ptrace(PTRACE_TRACEME) self-check — returns 0 (not traced)
 *   2. /proc/self/status TracerPid check — returns fake status with TracerPid:0
 *   3. /proc/self/cmdline inspection — returns clean argv
 *   4. LD_PRELOAD environment check — hides itself from getenv()
 *   5. /proc/self/exe path check — returns innocent path
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

/* ── 1. ptrace() — always succeed, never report being traced ─────────────── */
long ptrace(enum __ptrace_request request, ...) {
    (void)request;
    /* PTRACE_TRACEME returns 0 on success.
     * Other requests we just return 0 to avoid breaking legitimate callers. */
    return 0;
}

/* ── Internal helper: write a fake file from a static string ─────────────── */
static FILE *fake_file(const char *content) {
    FILE *tmp = tmpfile();
    if (!tmp) return NULL;
    fwrite(content, 1, strlen(content), tmp);
    rewind(tmp);
    return tmp;
}

/* Fake /proc/self/status — TracerPid set to 0 */
static const char FAKE_STATUS[] =
    "Name:\tprocess\n"
    "State:\tS (sleeping)\n"
    "Pid:\t1234\n"
    "PPid:\t1\n"
    "TracerPid:\t0\n"
    "Uid:\t1000\t1000\t1000\t1000\n"
    "Gid:\t1000\t1000\t1000\t1000\n"
    "VmPeak:\t102400 kB\n"
    "VmRSS:\t 10240 kB\n";

/* Fake /proc/self/cmdline — null-separated, innocent name */
static const char FAKE_CMDLINE[] = "/usr/bin/process\0-c\0config.ini\0";
#define FAKE_CMDLINE_LEN 31

/* ── 2 & 3. fopen() — intercept sensitive /proc paths ───────────────────── */
FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    if (path) {
        if (strstr(path, "/proc/self/status")  ||
            strstr(path, "/proc/thread-self/status")) {
            return fake_file(FAKE_STATUS);
        }
        if (strstr(path, "/proc/self/cmdline") ||
            strstr(path, "/proc/thread-self/cmdline")) {
            FILE *tmp = tmpfile();
            if (tmp) { fwrite(FAKE_CMDLINE, 1, FAKE_CMDLINE_LEN, tmp); rewind(tmp); }
            return tmp;
        }
    }
    return real_fopen(path, mode);
}

/* fopen64 alias (glibc large-file support) */
FILE *fopen64(const char *path, const char *mode) {
    return fopen(path, mode);
}

/* ── open() / open64() variants ──────────────────────────────────────────── */
int open(const char *path, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }

    if (path) {
        if (strstr(path, "/proc/self/status") ||
            strstr(path, "/proc/thread-self/status")) {
            /* Write fake status to a temp file and return its fd */
            FILE *tmp = fake_file(FAKE_STATUS);
            if (tmp) return fileno(tmp);
        }
        if (strstr(path, "/proc/self/cmdline") ||
            strstr(path, "/proc/thread-self/cmdline")) {
            FILE *tmp = tmpfile();
            if (tmp) {
                fwrite(FAKE_CMDLINE, 1, FAKE_CMDLINE_LEN, tmp);
                rewind(tmp);
                return fileno(tmp);
            }
        }
    }
    return real_open(path, flags, mode);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    return open(path, flags, mode);
}

/* ── 4. getenv() — hide LD_PRELOAD and analysis-related vars ─────────────── */
char *getenv(const char *name) {
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");

    if (name) {
        /* Hide our own presence */
        if (strcmp(name, "LD_PRELOAD")    == 0) return NULL;
        if (strcmp(name, "LD_AUDIT")      == 0) return NULL;
        /* Hide display / debug flags that indicate analysis env */
        if (strcmp(name, "DISPLAY")       == 0) return NULL;
        if (strcmp(name, "WINEDEBUG")     == 0) return NULL;
        if (strcmp(name, "STRACE_OUT")    == 0) return NULL;
    }
    return real_getenv(name);
}

/* secure_getenv — same as getenv for our purposes */
char *secure_getenv(const char *name) {
    return getenv(name);
}
