> [!NOTE]
> **Technica 2026: Frozen Hackathon Artifact**
>
> This repository preserves the Linux Syscall Tracer that won the Cipher Tech Best Digital Forensics Hack at Technica 2026. The original hackathon-winning version is permanently preserved under the `v1.0-technica` tag.
>
> The implementation is intentionally frozen and will not be extended with new features.
>
> A security research artifact evaluating the frozen tracer is now available:
>
> **[Tracing Linux Process Behavior with ptrace: Building and Evaluating a Syscall-Level Forensics Tool](article/Tracing_Linux_Process_Behavior_with_ptrace.pdf)**
>
> The article examines the tracer's `ptrace` architecture, evaluates its syscall-level output against controlled workloads with known ground truth, and separates limitations of the frozen implementation from limitations of `ptrace` and the syscall boundary itself.
>
> The original evaluation evidence is preserved separately under [`evaluation/2026-10-25-ptrace-article/`](evaluation/2026-10-25-ptrace-article/) and the `eval-2026-10-25` tag.

# Linux Syscall Tracer

A small `strace` clone written in C on top of `ptrace`. It runs a program, stops it at every system call, and prints the call's name, arguments, and return value. Built as a reverse-engineering aid for malware analysis and digital forensics: it shows what an unknown binary actually does (which files it opens, what it executes, which sockets it connects to) without needing its source.

## Build and run

Requires Linux on x86_64 (WSL2 works), `gcc`, and `make`.

```
make
./tracer <program> [args...]
make clean
```

Example:

```
./tracer ls -l /tmp
./tracer sh -c 'exec ls'
```

The trace is written to stderr and the traced program's own output stays on stdout, so the two can be separated:

```
./tracer ls -l /tmp 2> trace.log
./tracer ls -l /tmp > /dev/null
```

On a terminal both streams still appear together. The tracer exits when the program does.

## Example output

Excerpt from tracing `sh -c 'exec ls -l -a -h /tmp ...'`:

```
execve("/usr/local/sbin/ls", ["ls", "-l", "-a", "-h", "/tmp", ...], 0x614cf989ed68) = -1 (No such file or directory)
execve("/usr/bin/ls", ["ls", "-l", "-a", "-h", "/tmp", ...], 0x614cf989ed68) = 0
brk(0x0) = 0x5d38e95c3000
openat(0xffffff9c, "/etc/ld.so.cache", 0x80000, 0x0) = 3
read(0x3, 0x7ffd50740ce8, 0x340) = 832
```

## What it does

- Traces a single process from its very first `execve`, including the failed attempts when the program is looked up through `PATH`.
- Prints each call as `name(args) = result`. Unknown syscall numbers print as `syscall_N(...)`.
- Decodes path arguments (for example `open`, `openat`, `stat`, `readlink`, `execve`) as strings read out of the traced program's memory. Strings are escaped and cut off at 64 bytes with `...`.
- Decodes the `argv` array of `execve` as a list of strings, up to 16 entries, then `...`.
- Decodes the buffer of `write` as an escaped string, using the count argument as its length (at most 63 bytes shown, then `...`).
- Prints failures as `= -1 (error text)`. `brk` and `mmap` results print in hex; other results print in decimal.
- Passes real signals through to the traced program unchanged.

## How it works

1. `fork`; the child calls `PTRACE_TRACEME`, stops itself with `SIGSTOP`, then calls `execvp`.
2. The parent sets `PTRACE_O_TRACESYSGOOD` (so syscall stops are distinguishable from signals) and `PTRACE_O_TRACEEXEC` (so a successful exec is reported as an event, not a stray `SIGTRAP`).
3. The parent loops on `PTRACE_SYSCALL` + `waitpid`. Syscall stops come in pairs: at entry it prints the name and arguments (the registers `rdi, rsi, rdx, r10, r8, r9`, with the number taken from `orig_rax`); at exit it prints the return value from `rax`.
4. Pointers are followed with `PTRACE_PEEKDATA`, since the traced program's memory is not directly readable from the tracer.

## Limitations

This is a deliberately small tool.

- x86_64 Linux only. Syscall numbers are architecture-specific.
- Single process only. Threads and child processes created by `fork`/`vfork`/`clone` are not followed (no `-f`), so what a child process does is not traced.
- Only about 65 common syscalls have names; everything else prints as `syscall_N(...)`.
- Arguments are raw hex values except path strings and the `execve` `argv`. Flags, structs, `envp`, and `read` buffers are not decoded. Only `write` buffers are decoded, not `writev`, `pwrite64`, or `sendto`.
- On a terminal, the traced program's output can still appear in the middle of a trace line. Redirect stderr to a file to get a clean trace.

## Layout

| File | Purpose |
|---|---|
| `tracer.c` | `ptrace` loop, memory reads, argument and return-value printing |
| `syscalls.c`, `syscalls.h` | syscall number to name and argument-count table; which arguments are paths |
| `Makefile` | `make` builds `tracer`, `make clean` removes it |
