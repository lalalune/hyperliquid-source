# RE-001: node #115 guarded element conversion 0x5d52c80

## Bounded question

What does routine `0x5d52c80` (FDE `0x5d52c80..0x5d52ce8`,
104 bytes) compute for one owner object, and how is its result
consumed by its one caller? The routine sits next to the
fallback lookup (`0x5d52b60`, mapped in an earlier packet) and
was listed as the next candidate after it: the lock-and-pop
routine at `0x5d52c80`.

## Answer, pinned to the target

The routine takes one argument -- an owner object pointer in
`rdi` -- and returns one 32-bit value. In order:

1. **Acquire.** Call `0x606ca40` with the member at owner
   `+0x9c8` (`lea 0x9c8(%rdi),%rbp` at `0x5d52c85`, then
   `mov %rbp,%rdi` at `0x5d52c90`, call at `0x5d52c97`).
   The acquire callee is opaque here: only its argument and
   its pairing with the release call below are pinned, not
   its internals.
2. **Select an element pointer P.** Load A = qword at owner
   `+0xb50` and compare it with the qword at owner `+0xb58`:
   - A != [owner `+0xb58`]: P = qword at (A `- 0x18`)
     (`mov -0x18(%rax),%rdi` at `0x5d52cb3`).
   - A == [owner `+0xb58`]: load E = qword at owner `+0xb68`,
     then P = qword at ([E `- 8`] `+ 0x200 - 0x18`)
     (`mov -0x8(%rdx),%rax` at `0x5d52cd0`,
     `add $0x200,%rax` at `0x5d52cd4`, back to `0x5d52cb3`).
3. **Convert.** Call `0x5f03b40` with P (call at `0x5d52cb7`).
   That callee is only 16 bytes and is pinned end to end
   (excerpt `predicate.txt`): it loads Q = qword at P, compares
   the qword at Q `+0x58` with zero, and returns Q with its low
   byte replaced by 1 when that qword is zero, else 0. The
   upper bytes of the returned `eax` are NOT cleared: `sete`
   writes only `%al`, so the caller receives Q's low 32 bits
   with the low byte replaced by the predicate bit.
4. **Release and return.** Call `0x60d52f0` with the same
   `+0x9c8` member (`mov %rbp,%rdi` at `0x5d52cbc`, call at
   `0x5d52cc1`), then return the converter's `eax` unchanged
   (`mov %eax,%ebx` at `0x5d52cbf`, `mov %ebx,%eax` at
   `0x5d52cca`). The release callee calls
   `pthread_mutex_unlock@plt`, which is the evidence that the
   `+0x9c8` member is a mutex-shaped object.

**Exception path.** The landing-pad entry at `0x5d52cdc`
(inside the routine FDE range) saves the exception object in
`rbx` and jumps to the cleanup block at `0x5d52c70`
(excerpt `cleanup.txt`), which releases the same `+0x9c8`
member and then calls `_Unwind_Resume`. So the guard is
released on the exception path too, never held across it.

**What is not a pop.** The routine stores nothing to the
owner object or to any element slot -- every write it
performs is to its own stack frame -- so no removal or
mutation of an element is claimed. The earlier working label
"lock-and-pop" is not carried into the claim: the pinned
behavior is acquire, select, convert, release, return.

**Trailing bytes.** There are no trailing bytes inside the
FDE range after the landing-pad jump
(`0x5d52ce3..0x5d52ce8`); the next routine starts at
`0x5d52ce8`. The `nop` at `0x5d52ccf` is alignment padding
between the normal return and the second selection branch,
inside the routine.

## Consumer (site + argument setup, pinned)

The census finds exactly one direct call site, no tail jumps:
`0x5e63c38`, inside the caller `0x5e62c50..0x5e65462`. The
caller's excerpt (not shipped; only the site, the caller FDE
range, and this setup are claimed) moves its `r15` into `rdi`
(`0x5e63c35`) before the call, and tests the returned low
byte at once (`test %al,%al` at `0x5e63c3d`,
`jne 0x5e63cf3`). So the caller's branch depends only on the
returned low byte -- which is exactly the converter's
predicate bit -- and the upper returned bytes are ignored
there. The caller's other behaviour is not pinned here.

## NOT claimed

What the owner object, the `+0x9c8` member, the slots at
`+0xb50`/`+0xb58`/`+0xb68`, or the elements denote; what the
acquire callee (`0x606ca40`) does internally; what the
converter callee's target object or its `+0x58` field mean
beyond the zero test; any removal or mutation of an element;
caller semantics beyond the site, the caller FDE range, the
argument setup, and the low-byte test above; or behaviour on
dangling pointers, a null owner (the routine reads its slots
unconditionally, so the model raises on a null owner, stated
openly), or an out-of-range selection (the binary
dereferences unchecked; the model raises instead, stated
openly).

## Evidence packet

- `main.txt`: the whole routine, verbatim, exactly as
  objdump emitted it. Instruction-level detail lives only in
  these excerpt text files, not in `records.json`.
- `predicate.txt`: the whole 16-byte converter callee,
  verbatim.
- `cleanup.txt`: the exception cleanup block, verbatim.
- `frames.txt`: the FDE lines for the routine, the cleanup
  block, the converter, the acquire and release callees, and
  the caller.
- `callers.tsv`: the one call site.
- `records.json`: semantic records only -- branch
  site/target pairs, selection rules, converter steps,
  exception-path steps, consumer setup. No per-instruction
  mnemonic list: mnemonics such as `endbr64` appear only in
  the verbatim excerpts, where they are genuine instructions
  present in the target binary, not placeholders.
- `verify.py` + `census.py` + `export_excerpts.py`: the
  verification code is committed in the packet, so the
  checker behind "ALL CHECKS PASSED" is visible in the diff
  instead of only claimed here.

## Reproduce

From the repository root, with the digest-verified node #115
binary at `work/hl-node-115.bin` (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
per `provenance/artifacts.json`):

```
objdump -d --start-address=0x5d52c80 --stop-address=0x5d52ce8 work/hl-node-115.bin
objdump -d --start-address=0x5f03b40 --stop-address=0x5f03b50 work/hl-node-115.bin
objdump -d --start-address=0x5d52c70 --stop-address=0x5d52c80 work/hl-node-115.bin
python3 research/work-items/RE-001-guarded-convert-52c80-115/verify.py
python3 tests/test_guarded_convert_52c80_115.py
```

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. Repository-wide gates (`make verify`, `make
test`, `make catalogue-check`) are not claimed here: the
baseline is affected by missing LFS material and by the
absence of cargo/rustc on this machine, as recorded in
earlier packets; the packet checker and the model tests are
the verification run for this change.

## Concrete next step

Decompose the caller `0x5e62c50..0x5e65462` around the
guarded-convert call: what object its `r15` denotes, and
what the `jne 0x5e63cf3` arm does when the predicate bit is
set. The acquire callee `0x606ca40` (FDE
`0x606ca40..0x606cc6a`) is a second decomposition candidate.
