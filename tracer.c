#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

//resume the stopped child until it exits, printing the raw number of each syscall it makes.
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
            if (in_syscall) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                    perror("ptrace(GETREGS)");
                    return 1;
                }
                //orig_rax over rax because orig_rax stores original syscall number for userspace and won't get overwritten
                printf("syscall(%llu)\n", regs.orig_rax);
            }
        } else {
            //a real signal for the child: hand it back on the next resume.
            sig = WSTOPSIG(status);
        }
    }

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
