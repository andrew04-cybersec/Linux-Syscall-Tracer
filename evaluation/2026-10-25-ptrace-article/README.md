# Evaluation artifacts: ptrace syscall tracer article (October 25, 2026)

This directory contains the evaluation evidence for the article
**"Tracing Linux Process Behavior with ptrace: Building and Evaluating a Syscall-Level Forensics Tool."**

The evaluation was performed on October 25, 2026 against the frozen hackathon implementation:

- Tag: `v1.0-technica`
- Commit: `36fc3c0ab3e413a6ea8f8750759d2fa9479c1ad3`

## Relationship to the frozen artifact

These files are published separately from `v1.0-technica` and are not part of that tag. Adding this
directory does not modify the frozen hackathon artifact: the tag still points to the commit above, and
no tracer source file was changed for the evaluation. This directory did not exist at the time of the
hackathon; it was added afterward to support the article.

The files are research and evaluation evidence. They do not add or represent new tracer functionality.
The tracer was not benchmarked; nothing here measures its performance.

## Environment

The traces were collected in the Ubuntu cloud evaluation environment documented in
[`ENVIRONMENT.md`](ENVIRONMENT.md), not in the original WSL2 development environment. Loader prefix
length, PIDs, addresses and possibly `cat`'s copy strategy may differ in other environments.

## Contents

- `helpers/`: the two C programs used as controlled workloads.
  - `write_case.c` (Workload B): creates `/tmp/tracer_case_study.txt` and writes `FORENSICS_TEST_2026` followed by a newline.
  - `connect_case.c` (Workload C): attempts a TCP connection to port 9 on 127.0.0.1, which was expected to be closed.
- `traces/`: the six original trace files, exactly as saved, plus `SHA256SUMS`.
  Each trace is the tracer's stderr output, one `name(args) = result` record per line.
- `traces/SHA256SUMS`: the SHA-256 hashes recorded for the six original traces at the time of the
  experiment. All six recovered trace files were verified against these recorded hashes before
  publication.

## Build

As recorded:

```sh
git -C Linux-Syscall-Tracer archive v1.0-technica | tar x   # into an empty directory
make
gcc -Wall -Wextra -O0 -o write_case write_case.c
gcc -Wall -Wextra -O0 -o connect_case connect_case.c
```

`make` uses the repository Makefile (`gcc -Wall -Wextra -g`). The helpers are dynamically linked and
were written in C to keep interpreter startup out of the traces.

## Runs and trace files

| Trace | Run | Command or procedure as recorded | stdout |
|---|---|---|---|
| `A2.trace` | Workload A (primary): `cat /etc/hostname`, stdout to a pipe | `env -i PATH=/usr/local/bin:/usr/bin:/bin ./tracer cat /etc/hostname 2>A2.trace \| od -c` | pipe to `od` (showed `vm\n`) |
| `A3.trace` | Workload A, `/dev/null` check | Same as A, with stdout redirected to `/dev/null` | `/dev/null`; trace identical to `A2.trace` apart from a PID |
| `A.trace` | Workload A (stdout to a file) | Same as A, with stdout redirected to the regular file `A.stdout` | `A.stdout` (contained `vm\n`) |
| `B.trace` | Workload B: file creation and write | `env -i PATH=/usr/local/bin:/usr/bin:/bin ./tracer ./write_case >B.stdout 2>B.trace` | `B.stdout` (empty) |
| `C.trace` | Workload C: TCP connect to a closed loopback port | `env -i PATH=/usr/local/bin:/usr/bin:/bin ./tracer ./connect_case >C.stdout 2>C.trace` | `C.stdout` (empty) |
| `D.trace` | Run D (supporting): interrupted sleep | `./tracer sleep 2 2>D.trace &`, then SIGTSTP sent with `kill -TSTP` to the traced `sleep` after 0.5 s | terminal |

The full commands for the `/dev/null` check and the stdout-to-a-file run were recorded only as
variations of the Workload A command, as described above.

### Run D: what was and was not preserved

- Run D's recorded command has no `env -i` prefix, so the clean-environment condition is not claimed for it.
- The exact `kill -TSTP` invocation, including how the traced `sleep`'s PID was obtained, was not preserved.
- After SIGTSTP, the traced `sleep`'s process state was read from `/proc` and showed S (sleeping) rather
  than T (stopped). The exact `/proc` inspection command was not preserved.

### Recorded outcomes

- The tracer exited 0 in every run.
- Run directly, `write_case` exits 0 and `connect_case` exits 2 (connect failed).
- After run B, `/tmp/tracer_case_study.txt` contained exactly `FORENSICS_TEST_2026` and a newline (20 bytes).
- Nothing was listening on 127.0.0.1:9 before run C.

## Not included

The verification runs cited in Section 3 of the article were not saved as trace files. Their results
are reported in the article text only.

## Verifying the traces

Compute the SHA-256 hash of each file in `traces/` and compare it with `SHA256SUMS`:

| File | SHA-256 |
|---|---|
| `A2.trace` | `72757abe12e7aa636ab8dc65cedebfc20f9b13ce0c82d670f0de8ad8e59be184` |
| `A3.trace` | `9cfa6c612985c3c51f86ec64f72e3c87378c5d6e1820d94257976b2185348c56` |
| `A.trace` | `c891899e51e0563c3160f8f929c8ae0f33b2bc80eba526b505045e65cc09722f` |
| `B.trace` | `0c165f0214050a0161d0999c2ebe1434f8f5514115ed2e259e59db59dbf2a30a` |
| `C.trace` | `27064046b4a4a3ff396ed8a8b171fa9b1a5c6e72393cb7b56c715a2c34ae45f9` |
| `D.trace` | `9eced3f0d536b391be78d73eb16b0278a980ecb17045f05e34517736b23bfcfa` |
