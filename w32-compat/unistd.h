/* POSIX compatability layer for blowpipe.h */
#ifndef W32_COMPAT_H
#define W32_COMPAT_H

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

typedef SSIZE_T ssize_t;

#define ECHO    1
#define TCSANOW 0
struct termios {
    int c_lflag;
};

#define O_RDONLY 1
#define O_RDWR   2

#define STDIN_FILENO   0
#define STDOUT_FILENO  1
#define URANDOM_FILENO 3
#define TTY_FILENO     4
#define FILE_FILENO    5

static HANDLE compat_file;

static int
open(const char *path, int flags)
{
    if (strcmp(path, "/dev/urandom") == 0) {
        return URANDOM_FILENO;
    } else if (strcmp(path, "/dev/tty") == 0) {
        return TTY_FILENO;
    } else {
        assert(flags == O_RDONLY);
        DWORD access = GENERIC_READ;
        DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        DWORD disp = OPEN_EXISTING;
        DWORD flags = FILE_ATTRIBUTE_NORMAL;
        compat_file = CreateFile(path, access, share, 0, disp, flags, 0);
        return compat_file == INVALID_HANDLE_VALUE ? -1 : FILE_FILENO;
    }
}

static int
close(int fd)
{
    switch (fd) {
        case URANDOM_FILENO:
        case TTY_FILENO:
            return 0;
        case FILE_FILENO:
            CloseHandle(compat_file);
            compat_file = INVALID_HANDLE_VALUE;
            return 0;
        default:
            abort();
    }
}

static ssize_t
read(int fd, void *buf, size_t len)
{
    switch (fd) {
        case STDIN_FILENO: {
            HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
            DWORD actual;
            BOOL r = ReadFile(in, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
            return actual;
        }
        case URANDOM_FILENO: {
            HCRYPTPROV h = 0;
            DWORD type = PROV_RSA_FULL;
            DWORD flags = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;
            if (!CryptAcquireContext(&h, 0, 0, type, flags) ||
                !CryptGenRandom(h, len, buf)) {
                errno = EIO;
                return -1;
            }
            CryptReleaseContext(h, 0);
            return len;
        }
        case TTY_FILENO: {
            DWORD access = GENERIC_READ;
            DWORD disp = OPEN_EXISTING;
            DWORD flags = FILE_ATTRIBUTE_NORMAL;
            HANDLE in = CreateFile("CONIN$", access, 0, 0, disp, flags, 0);
            if (in == INVALID_HANDLE_VALUE) {
                errno = EIO;
                return -1;
            }

            DWORD actual;
            BOOL r = ReadConsole(in, buf, len, &actual, 0);
            if (!r) {
                CloseHandle(in);
                errno = EIO;
                return -1;
            }
            CloseHandle(in);
            return actual;
        }
        case FILE_FILENO: {
            DWORD actual;
            BOOL r = ReadFile(compat_file, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
            return actual;
        }
        default:
            abort();
    }
}

static ssize_t
write(int fd, const void *buf, size_t len)
{
    switch (fd) {
        case STDOUT_FILENO: {
            HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD actual;
            BOOL r = WriteFile(out, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
            return actual;
        }
        case TTY_FILENO: {
            DWORD access = GENERIC_WRITE;
            DWORD disp = OPEN_EXISTING;
            DWORD flags = FILE_ATTRIBUTE_NORMAL;
            HANDLE out = CreateFile("CONOUT$", access, 0, 0, disp, flags, 0);
            if (out == INVALID_HANDLE_VALUE) {
                errno = EIO;
                return -1;
            }
            DWORD actual;
            BOOL r = WriteConsole(out, buf, len, &actual, 0);
            if (!r) {
                CloseHandle(out);
                errno = EIO;
                return -1;
            }
            CloseHandle(out);
            return actual;
        }
        default:
            abort();
    }
}


static int
tcgetattr(int fd, struct termios *s)
{
    assert(fd == TTY_FILENO);
    s->c_lflag = 1;
    return 0;
}

static int
tcsetattr(int fd, int actions, struct termios *s)
{
    assert(fd == TTY_FILENO);
    assert(actions == TCSANOW);
    DWORD access = GENERIC_READ | GENERIC_WRITE;
    DWORD disp = OPEN_EXISTING;
    DWORD flags = FILE_ATTRIBUTE_NORMAL;
    HANDLE console = CreateFile("CONIN$", access, 0, 0, disp, flags, 0);
    if (console != INVALID_HANDLE_VALUE) {
        DWORD orig;
        if (GetConsoleMode(console, &orig)) {
            if (s->c_lflag)
                SetConsoleMode(console, orig | ENABLE_ECHO_INPUT);
            else
                SetConsoleMode(console, orig & ~ENABLE_ECHO_INPUT);
        }
    }
    return 0;
}

#endif
