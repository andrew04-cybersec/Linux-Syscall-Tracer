#ifndef SYSCALLS_H
#define SYSCALLS_H

// Name of an x86_64 Linux syscall, or NULL if it is not in our table.
const char *syscall_name(long nr);

// Number of arguments the syscall takes, or -1 if it is not in our table.
int syscall_nargs(long nr);

#endif
