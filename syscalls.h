#ifndef SYSCALLS_H
#define SYSCALLS_H

// Name of an x86_64 Linux syscall, or NULL if it is not in our table.
const char *syscall_name(long nr);

#endif
