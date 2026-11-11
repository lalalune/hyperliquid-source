# RE-001: map node #115 object teardown 0x5d56f50 with its record loop and 28 callers

Bounded question: what does node #115 routine 0x5d56f50 (FDE
0x5d56f50..0x5d573e1, 1169 bytes) do to the object in rdi, end to end?

## Answer

It is an object member teardown, not a destructor: it destroys the
object's members in a fixed order, but never frees the object itself,
never reads a vtable slot, and performs no canary check. It pushes
r15/r14/r13/r12/rbp/rbx and reserves 8 bytes of stack.

Phases, in order (full detail in records.json):

1. +0x1f0 pointer: if non-null, call 0x5f3c850 with it (call-shape
   only), then a sized delete of 0x10.
2. +0x148 flag: zeroed when nonzero.
3. +0x198 buffer (reset-capable; capacity end +0x1a8).
4. Record loop over [+0x130, +0x138) with stride 0x218. Per record:
   +0x210 pointer (call 0x5d8d820 + sized delete 0x290 when non-null);
   the +0x68 count walks a string array at +0x1f0 in reverse (stride
   0x30), disposing each string and ending at 0; the string vector at
   +0x1f8/+0x200 is disposed forward (stride 0x30), its end reset to
   begin when non-empty, and its buffer freed (capacity end +0x208);
   the +0x00 flag zeroed when nonzero; the +0x50 buffer freed
   (reset-capable, capacity end +0x60), with the record pointer
   advanced before the free. A second loop over the same +0x1f8 range
   is present but unreachable: its entry test compares the reloaded
   begin against the same begin value, so it always jumps to the
   buffer free.
5. Record array buffer freed (begin +0x130, capacity end +0x140).
6. +0xc8 flag zeroed when nonzero.
7. +0x118 buffer (reset-capable; capacity end +0x128).
8. Call 0x5d35c30 with object+0xb0 (call-shape only).
9. +0x98 buffer, then +0x80 buffer (free-only).
10. String vector at +0x68/+0x70 (stride 0x28; string at element +0x08,
    short-form address element +0x18), then its buffer freed.
11. +0x50 buffer (free-only).
12. Element loop at +0x38/+0x40 (stride 0x40): per element, the +0x38
    pointer, when non-null, is passed to 0x5d350c0 (call-shape only),
    then the +0x08 string is disposed; then the buffer is freed.
13. Element loop at +0x08/+0x10 (stride 0x40): per element, the +0x20
    string then the +0x00 string are disposed; then the buffer exit:
    a tail jump to the sized-delete PLT when the buffer is non-null,
    or a plain return when it is null.

String rule everywhere: short form (data pointer equals string
address + 0x10) frees nothing, otherwise a sized delete of (pointer,
capacity + 1) with capacity at string + 0x10.

Consumers: exactly 28 direct calls + 0 tail jumps across 26 caller
FDEs (see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations. The routine is reached only by code, never by
data. One caller was spot-checked for the argument: the caller at
0x5d5d18a..0x5d5d2c1 loads the object into rdi before the call at
0x5d5d1ca.

## Evidence

- `main.txt`: the whole routine, verbatim objdump output (the only
  modification is the binary name in the header, normalized to the
  bare name).
- `caller_sites.txt`: a verbatim 32-byte objdump window starting
  exactly at each of the 28 call sites. Whole-function caller excerpts
  were deliberately not included: with 26 caller FDEs they would be
  far larger than the packet, and on the neighbouring #2719 packet a
  large caller excerpt could not be supplied as a patch by GitHub and
  went unreviewed. `frames.txt` still carries every caller FDE, and
  `census.py` re-confirms every site against a fresh objdump run.
- `frames.txt`: the routine FDE plus all 26 caller FDEs.
- `callers.tsv`: every site with its kind and caller FDE.
- `relocations.txt`: "none" (no stored references).
- `records.json`: semantic records only. Instruction-level detail
  lives only in the raw disassembly excerpt text files, kept verbatim
  and whole-function. Mnemonics such as `endbr64` in the excerpts are
  genuine instructions present in the target binary, not placeholders.
- `verify.py`, `export_excerpts.py`, `census.py`: runnable checkers
  in the packet. Run `python3 verify.py` from the repository root.
- `tools/object_teardown_56f50_115.py` + tests in
  `tests/test_object_teardown_56f50_115.py`: the Python model and its
  tests, exercising the behavior end to end (inputs through the model
  to observable outputs), not only pinned constants.

## Binding

Artifact: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
as recorded in `provenance/artifacts.json`. The local copy
`work/hl-node-115.bin` hashes to the same digest. The objdump command
for the main excerpt was:

```
objdump -d --start-address=0x5d56f50 --stop-address=0x5d573e1 work/hl-node-115.bin
```

## Assumptions and unknowns

- Field labels describe observed pointer arithmetic only, not
  confirmed source-level types.
- The 0x5f3c850, 0x5d8d820, 0x5d35c30 and 0x5d350c0 callees are
  recorded as call-shape only; their semantics are not pinned.
- The +0x1f0 string array's buffer ownership is not pinned: its
  strings are disposed here but its buffer is not freed here.
- Distinct from the neighbouring 0x5d573f0 member-tree teardown
  (open PR #2719): that routine unrolls a 9-level tree walk with
  self-recursion over 0x58-byte nodes, while this routine walks a
  flat record array plus four independent member vectors and has no
  recursion.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
doctor` exits non-zero on the pre-existing missing Rust/Ghidra
toolchains; `make verify`, `make test` and `make catalogue-check`
were not run in a tooled environment and no hosted CI result is
claimed. The packet's own `verify.py` was run and passes.
