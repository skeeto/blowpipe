/* POSIX compatability layer for Blowpipe
 *
 * Only the tiny, tiny subset of POSIX needed by Blowpipe is implemented.
 */
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
static HANDLE compat_conin;
static HANDLE compat_conout;
static HCRYPTPROV compat_crypt;

static int
open(const char *path, int flags)
{
    if (strcmp(path, "/dev/urandom") == 0) {
        DWORD type = PROV_RSA_FULL;
        DWORD flags = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;
        if (!CryptAcquireContext(&compat_crypt, 0, 0, type, flags)) {
            errno = EACCES;
            return -1;
        }
        return URANDOM_FILENO;
    } else if (strcmp(path, "/dev/tty") == 0) {
        DWORD access = GENERIC_READ | GENERIC_WRITE;
        DWORD disp = OPEN_EXISTING;
        DWORD flags = FILE_ATTRIBUTE_NORMAL;
        compat_conin = CreateFile("CONIN$", access, 0, 0, disp, flags, 0);
        if (compat_conin == INVALID_HANDLE_VALUE) {
            errno = ENOENT;
            return -1;
        }
        compat_conout = CreateFile("CONOUT$", access, 0, 0, disp, flags, 0);
        if (compat_conout == INVALID_HANDLE_VALUE) {
            CloseHandle(compat_conin);
            errno = ENOENT;
            return -1;
        }
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
            CryptReleaseContext(compat_crypt, 0);
            return 0;
        case TTY_FILENO:
            CloseHandle(compat_conin);
            CloseHandle(compat_conout);
            return 0;
        case FILE_FILENO:
            CloseHandle(compat_file);
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
            static HANDLE in = INVALID_HANDLE_VALUE;
            static BOOL isconsole;
            if (in == INVALID_HANDLE_VALUE) {
                in = GetStdHandle(STD_INPUT_HANDLE);
                DWORD mode;
                isconsole = GetConsoleMode(in, &mode);
            }
            if (len > 0x77e8 && isconsole) {
                /* Undocumented behavior: Console reads are limited to 30696
                 * bytes. Larger reads trigger ERROR_NOT_ENOUGH_MEMORY.
                 * Y U do dis, Microsoft?
                 */
                len = 0x77e8;
            }
            DWORD actual;
            BOOL r = ReadFile(in, buf, len, &actual, 0);
            if (!r) {
                DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE)
                    return 0; // actually an EOF
                errno = EIO;
                return -1;
            }
            return actual;
        }
        case URANDOM_FILENO: {
            if (!CryptGenRandom(compat_crypt, len, buf)) {
                errno = EIO;
                return -1;
            }
            return len;
        }
        case TTY_FILENO: {
            DWORD actual;
            BOOL r = ReadConsole(compat_conin, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
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
            DWORD actual;
            BOOL r = WriteConsole(compat_conout, buf, len, &actual, 0);
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
