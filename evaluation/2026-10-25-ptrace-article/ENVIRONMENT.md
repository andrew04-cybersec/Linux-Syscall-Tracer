# Evaluation environment

This file records the environment used for the October 25, 2026 evaluation of the frozen
`v1.0-technica` tracer. All traces in `traces/` were collected here.

**This is a cloud evaluation environment, not the original development environment.** The tracer was
originally developed on WSL2. None of the traces in this directory were collected on that WSL2 system,
and results there may differ (for example, loader prefix length, PIDs, addresses and possibly `cat`'s
copy strategy).

## System

| Item | Value |
|---|---|
| Date | October 25, 2026 |
| Architecture | x86_64 |
| Operating system | Ubuntu 24.04.5 LTS (cloud container) |
| Kernel | 6.18.44-fc-v153 |
| C library | GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39 |
| Compiler (tracer and helpers) | gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 |
| coreutils (`cat`) | GNU coreutils 9.4 |

## Evaluated tracer

| Item | Value |
|---|---|
| Tag | `v1.0-technica` |
| Commit | `36fc3c0ab3e413a6ea8f8750759d2fa9479c1ad3` |
| Build | repository Makefile (`gcc -Wall -Wextra -g`) |

## Workload conditions

| Item | Value |
|---|---|
| `/etc/hostname` contents | `vm\n` (3 bytes) |
| Primary runs A, B, C and the two Workload A stdout checks | each started with `env -i PATH=/usr/local/bin:/usr/bin:/bin` |
| Supporting run D | recorded as `./tracer sleep 2 2>D.trace &`, with no `env -i` prefix; a clean environment is not claimed for run D |
| Helper builds | `gcc -Wall -Wextra -O0`; dynamically linked |
