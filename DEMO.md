# Demo Script

Run these from the project directory on Linux (WSL2 works). Each step has the command and what to point out.

## 0. Build

```
make
```

Say: a small C program, a few hundred lines, built on `ptrace`, no dependencies.

## 1. The basics: every syscall, with arguments and results

```
./tracer echo hello 2> trace.log
head -5 trace.log
```

Point out:
- `hello` printed on the terminal (the program's output) and the trace went to the file (stderr), so they stay separate.
- The first line is the program's own `execve`, with its path and `argv` decoded.
- Each line is `name(args) = result`.

## 2. Process launches: the execve chain

```
./tracer sh -c 'exec ls' 2>&1 >/dev/null | grep execve
```

Point out:
- The first `execve` is the shell, the second is `ls` replacing it.
- The failed lookups (`No such file or directory`) show how the program searched `PATH`.
- For malware analysis, this is how you see what a sample launches.

## 3. File access: what a program opens and reads

```
./tracer cat /etc/hostname 2> trace.log
grep -E 'openat|read' trace.log
```

Point out:
- Paths are read out of the traced program's memory and printed as strings.
- You can see the libraries it loads and the file it actually opens.
- Failed opens show the error text, such as `No such file or directory`.

## 4. What it writes: buffer contents

```
./tracer echo secret 2>&1 >/dev/null | grep write
```

Point out:
- The buffer of `write` is decoded as a string using the count argument as its length.
- Binary data is shown with `\x..` escapes and long buffers are cut off with `...`.

## 5. Sockets

```
./tracer ls -l /etc 2>&1 >/dev/null | grep -E 'socket|connect'
```

Point out:
- You can see that a program opens sockets and attempts connections even when the program itself shows nothing.
- Limitation: the address is still a raw pointer, which is a possible next step.

If `curl` is installed and you have network access, this also works:

```
./tracer curl -s http://example.com 2>&1 >/dev/null | grep -E 'socket|connect'
```

## 6. Limitations (say these before they ask)

```
./tracer sh -c 'ls' 2>&1 >/dev/null | grep -E 'vfork|wait4'
```

Point out:
- The shell starts `ls` as a child (`vfork`), and the trace shows only the parent. Following child processes and threads is out of scope for this version.
- Only about 65 syscalls have names, only x86_64 is supported, and only `write` buffers are decoded.

## 7. Clean up

```
make clean
```
