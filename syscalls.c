#include <stddef.h>
#include "syscalls.h"

struct syscall_entry {
    long nr;
    const char *name;
};

//table specified to x86_64 architecture because each architecture has its own syscall numbers.
static const struct syscall_entry table[] = {
    {0, "read"},
    {1, "write"},
    {2, "open"},
    {3, "close"},
    {4, "stat"},
    {5, "fstat"},
    {6, "lstat"},
    {8, "lseek"},
    {9, "mmap"},
    {10, "mprotect"},
    {11, "munmap"},
    {12, "brk"},
    {13, "rt_sigaction"},
    {14, "rt_sigprocmask"},
    {16, "ioctl"},
    {17, "pread64"},
    {21, "access"},
    {22, "pipe"},
    {32, "dup"},
    {33, "dup2"},
    {35, "nanosleep"},
    {39, "getpid"},
    {41, "socket"},
    {42, "connect"},
    {56, "clone"},
    {57, "fork"},
    {59, "execve"},
    {60, "exit"},
    {61, "wait4"},
    {62, "kill"},
    {63, "uname"},
    {72, "fcntl"},
    {79, "getcwd"},
    {80, "chdir"},
    {87, "unlink"},
    {89, "readlink"},
    {101, "ptrace"},
    {102, "getuid"},
    {137, "statfs"},
    {157, "prctl"},
    {158, "arch_prctl"},
    {202, "futex"},
    {217, "getdents64"},
    {218, "set_tid_address"},
    {228, "clock_gettime"},
    {231, "exit_group"},
    {257, "openat"},
    {262, "newfstatat"},
    {273, "set_robust_list"},
    {302, "prlimit64"},
    {318, "getrandom"},
    {334, "rseq"},
};

const char *syscall_name(long nr)
{
    //the caller handles the return null case so the program doesn't crash
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].nr == nr)
            return table[i].name;
    }
    return NULL;
}
