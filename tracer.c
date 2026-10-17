#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "syscalls.h"

#define MAX_STR 64

//copy a NUL-terminated string out of the child's memory into buf (at most max-1 chars).
//returns 0 if complete, 1 if cut off at max, -1 if the child's memory could not be read.
static int read_string(pid_t pid, unsigned long long addr, char *buf, size_t max)
{
    size_t len = 0;

    while (len < max - 1) {
        errno = 0;
        //we can't just dereference the pointer because it is in the child's address space, not ours so we won't have a mapping for that address. PTRACE_PEEKDATA instead can just read something in the tracee's memory as a word and return it as the result of the ptrace() call.
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + len), NULL);
        //we check the errno here instead of comparing word to -1 because -1 could be an error or actual data so we set errno to 0 beforehand and only treat -1 as an error if errno was set.
        if (word == -1 && errno != 0)
            return -1;
        for (size_t i = 0; i < sizeof(word) && len < max - 1; i++) {
            char c = (char)(word >> (8 * i));
            if (c == '\0') {
                buf[len] = '\0';
                return 0;
            }
            buf[len++] = c;
        }
    }
    buf[len] = '\0';
    return 1;
}

//print s in double quotes, escaping anything that would mess up the terminal or hide data.
static void print_string(const char *s, int truncated)
{
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\')
            printf("\\%c", *s);
        else if (*s == '\n')
            printf("\\n");
        else if (isprint((unsigned char)*s))
            putchar(*s);
        else
            printf("\\x%02x", (unsigned char)*s);
    }
    putchar('"');
    if (truncated)
        printf("...");
}

//print the first n syscall arguments as raw hex values, except path arguments, which are read from the child and shown as strings. n < 0 means the syscall is unknown, so print "...".
static void print_args(pid_t pid, const struct user_regs_struct *regs, int n)
{
    int path_arg = syscall_path_arg((long)regs->orig_rax);
    char buf[MAX_STR];

    //the registers that carry the arguments are: rdi, rsi, rdx, r10, r8, r9
    //4th register is r10 instead of rcx because rcx is destroyed by hardware syscall instruction so r10 replaces it.
    unsigned long long args[6] = { regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9 };

    if (n < 0) {
        printf("...");
        return;
    }
    for (int i = 0; i < n; i++) {
        printf("%s", i ? ", " : "");
        int rc = (i == path_arg) ? read_string(pid, args[i], buf, sizeof(buf)) : -1;
        if (rc >= 0)
            print_string(buf, rc);
        else
            printf("0x%llx", args[i]);
    }
}

//resume the stopped child until it exits, printing the name, arguments, and return value.
static int trace_loop(pid_t pid)
{
    //PTRACE_O_TRACESYSGOOD: when the kernel delivers system call traps it sets bit 7 in the signal number which makes it easier for the tracer to distinguish normal traps from system call traps.
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
        perror("ptrace(SETOPTIONS)");
        return 1;
    }

    int status;
    int in_syscall = 0;
    int sig = 0;

    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig) == -1) {
            perror("ptrace(SYSCALL)");
            return 1;
        }
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            sig = 0;
            //syscall stops come in pairs, entry then exit. in_syscall flips on every stop, so it tells us which one this is.
            in_syscall = !in_syscall;
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                perror("ptrace(GETREGS)");
                return 1;
            }
            if (in_syscall) {
                //orig_rax over rax because orig_rax stores original syscall number for userspace and won't get overwritten
                const char *name = syscall_name((long)regs.orig_rax);
                if (name)
                    printf("%s(", name);
                else
                    printf("syscall_%llu(", regs.orig_rax);
                //we print arguments at entry stop rather than exit stop because if we wait until exit stop then we will lose the arguments.
                print_args(pid, &regs, syscall_nargs((long)regs.orig_rax));
                printf(")");
                //flush so our output stays in order with whatever the child writes before this syscall returns.
                fflush(stdout);
            } else {
                //read rax at the exit stop because at entry stop it only holds -ENOSYS (-38) which is a placeholder for the function not being implemented.
                long long ret = (long long)regs.rax;
                //-4095 and -1 means failure as that space is reserved for errors. Errno is basically just an integer value that stores errors and we negate the value before strerror turns it into text.
                if (ret < 0 && ret >= -4095)
                    printf(" = -1 (%s)\n", strerror((int)-ret));
                //print brk and mmap results in hex whereas the rest are in decimal because it works directly in the memory address space
                else if (regs.orig_rax == SYS_brk || regs.orig_rax == SYS_mmap)
                    printf(" = 0x%llx\n", ret);
                else
                    printf(" = %lld\n", ret);
            }
        } else {
            //a real signal for the child: hand it back on the next resume.
            sig = WSTOPSIG(status);
        }
    }

    //in_syscall can still be set after the loop because exit_group causes the kernel to never produce an exit stop for it since it terminates all threads.
    if (in_syscall)
        printf(" = ?\n");

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        //PTRACE_TRACEME: child flags itself to be traced by parent prior to executing. child is the one to execute since the parent needs the permission to trace it.
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(TRACEME)");
            _exit(1);
        }

        //child process stops before new program runs so the parent can act before it runs, i.e. set specified options
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(1);
    }

    int status;
    //waitpid waits for child process state to change and records exit status or stopping signal
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child did not stop after exec\n");
        return 1;
    }

    return trace_loop(pid);
}
