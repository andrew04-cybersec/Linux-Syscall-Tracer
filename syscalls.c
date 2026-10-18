#include <stddef.h>
#include <sys/syscall.h>
#include "syscalls.h"

struct syscall_entry {
    long nr;
    const char *name;
    int nargs;
};

//table specified to x86_64 architecture because each architecture has its own syscall numbers.
static const struct syscall_entry table[] = {
    {0, "read", 3},
    {1, "write", 3},
    {2, "open", 3},
    {3, "close", 1},
    {4, "stat", 2},
    {5, "fstat", 2},
    {6, "lstat", 2},
    {7, "poll", 3},
    {8, "lseek", 3},
    {9, "mmap", 6},
    {10, "mprotect", 3},
    {11, "munmap", 2},
    {12, "brk", 1},
    {13, "rt_sigaction", 4},
    {14, "rt_sigprocmask", 4},
    {15, "rt_sigreturn", 0},
    {16, "ioctl", 3},
    {17, "pread64", 4},
    {19, "readv", 3},
    {20, "writev", 3},
    {21, "access", 2},
    {22, "pipe", 1},
    {32, "dup", 1},
    {33, "dup2", 2},
    {35, "nanosleep", 2},
    {39, "getpid", 0},
    {41, "socket", 3},
    {42, "connect", 3},
    {56, "clone", 5},
    {57, "fork", 0},
    //vfork prints the pid of the new child as its return value since that is what the parent gets back. the child's activity is missing from the trace because we only trace the original process and never set the ptrace options that follow forks, so the kernel never attaches the child to our tracer and its syscalls never stop for us.
    {58, "vfork", 0},
    {59, "execve", 3},
    {60, "exit", 1},
    {61, "wait4", 4},
    {62, "kill", 2},
    {63, "uname", 1},
    {72, "fcntl", 3},
    {78, "getdents", 3},
    {79, "getcwd", 2},
    {80, "chdir", 1},
    {87, "unlink", 1},
    {89, "readlink", 3},
    {101, "ptrace", 4},
    {102, "getuid", 0},
    {104, "getgid", 0},
    {107, "geteuid", 0},
    {108, "getegid", 0},
    {110, "getppid", 0},
    {131, "sigaltstack", 2},
    {137, "statfs", 2},
    {157, "prctl", 5},
    {158, "arch_prctl", 2},
    {192, "lgetxattr", 4},
    {194, "listxattr", 3},
    {202, "futex", 6},
    {217, "getdents64", 3},
    {218, "set_tid_address", 1},
    {228, "clock_gettime", 2},
    {231, "exit_group", 1},
    {257, "openat", 4},
    {262, "newfstatat", 4},
    {273, "set_robust_list", 2},
    {292, "dup3", 3},
    {293, "pipe2", 2},
    {302, "prlimit64", 4},
    {318, "getrandom", 3},
    {332, "statx", 5},
    {334, "rseq", 4},
};

static const struct syscall_entry *find(long nr)
{
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].nr == nr)
            return &table[i];
    }
    return NULL;
}

const char *syscall_name(long nr)
{
    //the caller handles the return null case so the program doesn't crash
    const struct syscall_entry *e = find(nr);
    return e ? e->name : NULL;
}

int syscall_nargs(long nr)
{
    const struct syscall_entry *e = find(nr);
    return e ? e->nargs : -1;
}

int syscall_path_arg(long nr)
{
    switch (nr) {
    case SYS_open:
    case SYS_access:
    case SYS_execve:
    case SYS_stat:
    case SYS_lstat:
    case SYS_statfs:
    case SYS_chdir:
    case SYS_unlink:
    case SYS_readlink:
    case SYS_lgetxattr:
    case SYS_listxattr:
        return 0;
    case SYS_openat:
    case SYS_newfstatat:
    //argument 0 of statx is a directory file descriptor that the path is resolved relative to, the same as in openat and newfstatat, so the path string is at index 1 instead of 0.
    case SYS_statx:
        return 1;
    default:
        return -1;
    }
}
