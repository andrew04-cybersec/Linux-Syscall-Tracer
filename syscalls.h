#ifndef SYSCALLS_H
#define SYSCALLS_H

//name of an x86_64 Linux syscall, or NULL if it is not in our table.
const char *syscall_name(long nr);

//number of arguments the syscall takes, or -1 if it is not in our table.
int syscall_nargs(long nr);

//index of the argument that is a path string (0-based), or -1 if the syscall has none we decode.
int syscall_path_arg(long nr);

#endif
