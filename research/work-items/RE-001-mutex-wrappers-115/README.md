# RE-001: mutex lock/unlock wrappers 0x60d5230 / 0x60d52f0 (node #115)

## Bounded question

What do the two small wrappers at `0x60d5230` and `0x60d52f0`
do with the single pointer they receive, which return codes
do they accept, and what happens on any other code? A third
piece belongs to the same behavior: the 9-byte stub at
`0x606ca00` that tail-jumps to the lock wrapper.

## Answer, end to end

The two wrappers are the same shape, 149 bytes each, differing
only in the pthread call they wrap and in the operation word
they report. Each takes one argument in rdi: the mutex
pointer, passed unchanged to the pthread call.

### Lock wrapper (0x60d5230..0x60d52c5)

1. Save the stack canary, then call `pthread_mutex_lock`
   with the mutex pointer.
2. Accept the result when `(result & ~0x10) == 0` — that is,
   result 0 or result 16 — or when the result is exactly 110.
   On any accepted code the canary is checked and the wrapper
   returns, having done nothing else.
3. On any other result code the wrapper takes the fatal path,
   in order: (a) build an error string by calling the
   741-byte builder `0x61d1f30` with (stack temp string, result
   code); what the builder computes inside is not pinned, only
   its argument list; (b) report with `__fprintf_chk` to the
   stream loaded through slot `0x64edcb8` (two loads: the slot
   holds a pointer, and the stream is what it points to),
   flag 2, format `pthread %s: %s\n` at `0x43742f`, arguments
   `lock` at `0x43fa29` and the built string's data pointer;
   (c) dispose the temp string; (d) call `abort`. The fatal
   path never returns.
4. A canary mismatch before the return goes to
   `__stack_chk_fail`, as usual.

### Unlock wrapper (0x60d52f0..0x60d5385)

Identical, with `pthread_mutex_unlock` in place of the lock
call and the operation word `unlock` at `0x43948f` in place
of `lock`. Same accepted codes (0, 16, 110), same fatal path
(builder, report, dispose, abort), same canary check.

### Landing-pad cleanups (not normal-flow exits)

Each wrapper ends with a landing-pad stub: the lock stub at
`0x60d52b9` jumps to the cleanup block at `0x60d5200`, and
the unlock stub at `0x60d5379` jumps to the cleanup block at
`0x60d52c6`. Both cleanups dispose the temp string, check
the canary, and resume unwinding. Their semantics beyond
dispose-and-resume are not claimed; neither block runs on
the success or fatal paths above.

### The lock stub (0x606ca00..0x606ca09)

A single tail jump to the lock wrapper, passing its argument
through unchanged. Its two direct callers are `0x606cb0f`
and `0x606cbea`, both inside the instrumented acquire
`0x606ca40` — so the instrumented acquire reaches the lock
wrapper through this stub, while the plain lock sites call
the wrapper directly.

## References

The wrappers are reached only by code, never by data: the
executable segment contains no stored qword equal to either
wrapper address and no RELATIVE relocation mentions them
(exhaustive E8/E9 scan with objdump confirmation, reproduced
by census.py). Counts: 157 direct calls to the lock wrapper
plus the stub's tail jump; 669 direct calls to the unlock
wrapper plus 5 tail jumps (`0x5d53182`, `0x5dfd030`,
`0x5e8633c`, `0x5e86bde`, `0x5e86c44`); 2 direct calls to the
stub. The full site lists are in `callers.tsv` (832 rows).
Two of the unlock sites are the release calls previous
RE-001 packets left opaque: `0x5d4e4fd` (the take-record
routine's release) and `0x5d4dcff` (the chain-reset routine's
release). The format and operation strings were verified
byte-for-byte against the binary: `pthread %s: %s\n`,
`lock`, `unlock`.

## Not claimed

What the error-string builder `0x61d1f30` computes inside
(only its argument list is pinned); what the stream slot
`0x64edcb8` denotes beyond holding the report stream;
caller semantics beyond sites; behavior on a null or
dangling mutex pointer (the model raises on null, stated
openly — the binary itself checks nothing before the pthread
call).

## Environment limits (stated openly)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
no Rust reconstruction is attempted and the binary is used
only through objdump/readelf and digest checks. The full
repository test suite was not run: pytest is not installed on
this VM, and the repo baseline failures are pre-existing
LFS-artifact failures unrelated to this change. The packet's
own model tests run with plain python3 and pass.
