#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include "syscalls.h"

#define MAX_STR 64
#define MAX_ARGV 16

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

//copy exactly len bytes out of the child's memory into buf. returns 0 on success, -1 if the child's memory could not be read.
static int read_bytes(pid_t pid, unsigned long long addr, char *buf, size_t len)
{
    for (size_t off = 0; off < len; off += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + off), NULL);
        if (word == -1 && errno != 0)
            return -1;
        //the last word can hold more bytes than we asked for so only copy what is left.
        size_t n = len - off < sizeof(word) ? len - off : sizeof(word);
        memcpy(buf + off, &word, n);
    }
    return 0;
}

//print len bytes of buf in double quotes, escaping anything that would mess up the terminal or hide data.
static void print_buffer(const char *buf, size_t len, int truncated)
{
    fputc('"', stderr);
    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (c == '"' || c == '\\')
            fprintf(stderr, "\\%c", c);
        else if (c == '\n')
            fprintf(stderr, "\\n");
        else if (isprint((unsigned char)c))
            fputc(c, stderr);
        else
            fprintf(stderr, "\\x%02x", (unsigned char)c);
    }
    fputc('"', stderr);
    if (truncated)
        fprintf(stderr, "...");
}

//print the NUL-terminated string s in double quotes.
static void print_string(const char *s, int truncated)
{
    print_buffer(s, strlen(s), truncated);
}

//print the NULL-terminated array of string pointers at addr in the child, e.g. ["ls", "-l"]. stops after MAX_ARGV entries or at the first unreadable pointer, ending with "..." in either case.
static void print_string_array(pid_t pid, unsigned long long addr)
{
    char buf[MAX_STR];
    int complete = 0;
    int i;

    //argv is a pointer to an array of pointers so the first read gets the pointer array and the second read gets the actual string data. this can only be done at the entry stop since after a successful execve the old address space is replaced and by the exit stop the pointers no longer point at the data you want to read.
    fputc('[', stderr);
    for (i = 0; i < MAX_ARGV; i++) {
        errno = 0;
        long ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * sizeof(long)), NULL);
        if (ptr == -1 && errno != 0)
            break;
        //what marks the end of the argv array is when it reaches the tail of the pointer array which is a NULL pointer and we can't just ask the kernel how many entries it has because execve takes no length arguement which means that the only thing it is received is the address of the array and therefore the only signal of where it ends is the Null sentinel.
        if (ptr == 0) {
            complete = 1;
            break;
        }
        fprintf(stderr, "%s", i ? ", " : "");
        int rc = read_string(pid, (unsigned long long)ptr, buf, sizeof(buf));
        if (rc >= 0)
            print_string(buf, rc);
        else
            fprintf(stderr, "0x%lx", ptr);
    }
    if (!complete)
        fprintf(stderr, "%s...", i ? ", " : "");
    fputc(']', stderr);
}

//print the buffer a write() is sending, read from the child at addr. count is the length the program asked to write, and at most MAX_STR - 1 bytes of it are shown.
static void print_written(pid_t pid, unsigned long long addr, unsigned long long count)
{
    char buf[MAX_STR];
    //a write buffer is not NUL-terminated and can hold any bytes, including zeros, so the length has to come from the count argument instead of from looking for a NUL like read_string does.
    size_t len = count < sizeof(buf) - 1 ? count : sizeof(buf) - 1;

    if (read_bytes(pid, addr, buf, len) == -1)
        fprintf(stderr, "0x%llx", addr);
    else
        print_buffer(buf, len, count > len);
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
        fprintf(stderr, "...");
        return;
    }
    for (int i = 0; i < n; i++) {
        fprintf(stderr, "%s", i ? ", " : "");
        if (regs->orig_rax == SYS_execve && i == 1) {
            print_string_array(pid, args[i]);
            continue;
        }
        //for write the buffer is argument 1 and its length is argument 2, so it is decoded here at the entry stop like the other pointers.
        if (regs->orig_rax == SYS_write && i == 1) {
            print_written(pid, args[1], args[2]);
            continue;
        }
        int rc = (i == path_arg) ? read_string(pid, args[i], buf, sizeof(buf)) : -1;
        if (rc >= 0)
            print_string(buf, rc);
        else
            fprintf(stderr, "0x%llx", args[i]);
    }
}

//resume the stopped child until it exits, printing the name, arguments, and return value.
static int trace_loop(pid_t pid)
{
    //PTRACE_O_TRACESYSGOOD: when the kernel delivers system call traps it sets bit 7 in the signal number which makes it easier for the tracer to distinguish normal traps from system call traps.
    //tracer can't tell the difference between a real SIGTRAP signal and an ordinary signal-delivery after successful execve when PTRACE_O_TRACEEXEC is not set so we set it so it can actually tell the difference and doesn't produce a plain signal delivery stop. 
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC) == -1) {
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
                    fprintf(stderr, "%s(", name);
                else
                    fprintf(stderr, "syscall_%llu(", regs.orig_rax);
                //we print arguments at entry stop rather than exit stop because if we wait until exit stop then we will lose the arguments.
                print_args(pid, &regs, syscall_nargs((long)regs.orig_rax));
                fprintf(stderr, ")");
                //the trace goes to stderr instead of stdout so it stays separate from the traced program's own output and can be redirected on its own, e.g. 2>trace.log. stderr is unbuffered so each piece is written immediately and no fflush is needed.
            } else {
                //read rax at the exit stop because at entry stop it only holds -ENOSYS (-38) which is a placeholder for the function not being implemented.
                long long ret = (long long)regs.rax;
                //-4095 and -1 means failure as that space is reserved for errors. Errno is basically just an integer value that stores errors and we negate the value before strerror turns it into text.
                if (ret < 0 && ret >= -4095)
                    fprintf(stderr, " = -1 (%s)\n", strerror((int)-ret));
                //print brk and mmap results in hex whereas the rest are in decimal because it works directly in the memory address space
                else if (regs.orig_rax == SYS_brk || regs.orig_rax == SYS_mmap)
                    fprintf(stderr, " = 0x%llx\n", ret);
                else
                    fprintf(stderr, " = %lld\n", ret);
            }
        } else {
            //wrong to hand child a SIGTRAP here because it turns a message meant for the tracer into a signal the child receives and therefore will terminate and dump core by default. status >> 16 can tell a ptrace event stop from a real signal stop because the upper bits hold the ptrace event code so the result is nonzero for an event stop and zero for an ordinary signal stop.
            if (status >> 16)
                sig = 0;
            else
                //a real signal for the child: hand it back on the next resume.
                sig = WSTOPSIG(status);
        }
    }

    //in_syscall can still be set after the loop because exit_group causes the kernel to never produce an exit stop for it since it terminates all threads.
    if (in_syscall)
        fprintf(stderr, " = ?\n");

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

        //child process stops itself here so that the trace_loop can set the options and the next syscall can be passed otherwise it would be invisible to the target program's own execve. The child can't just wait for the stop because it comes after the execve has already finished so the call has gone by before the tracer can watch for it.
        raise(SIGSTOP);
        //If the tracer resumed with SIGSTOP and not sig = 0 then it would just stop again after being given the signal whereas if you supress the signal then it can keep running. 
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
        fprintf(stderr, "child did not stop before exec\n");
        return 1;
    }

    return trace_loop(pid);
}
