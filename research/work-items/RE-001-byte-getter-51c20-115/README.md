# RE-001: node #115 one-byte getter 0x5d51c20

## Bounded question

What does routine `0x5d51c20` (FDE `0x5d51c20..0x5d51c64`, 68 bytes)
return for a given flag byte, selector, vector and default byte,
and what does it leave unread?

## Answer, pinned to the target

The routine takes two arguments -- a flag-holder pointer in `rdi`
(only its first byte is read) and an object pointer in `rsi` --
makes no calls, writes nothing, and returns exactly one byte. The
decision, in order:

1. If the flag byte at `(rdi)` is NOT exactly 1, the selector at
   object `+0x100` is never read. Return the first byte of the
   vector at `+0x1c8` (begin) / `+0x1d0` (end) when begin differs
   from end, else the default byte at `+0x153`. Note the test is
   equality with 1 (`cmpb $0x1` + `je`), not truthiness: flag
   values 0, 2, 255 all take this path.
2. If the flag byte IS 1, read the signed 32-bit selector at
   `+0x100`. If it is >= 0 (`jns` after `test`), return literal
   0 -- the vector and the default byte are never read on this
   path.
3. If the flag byte is 1 and the selector is negative, fall back
   to the vector rule of step 1: first byte when the vector is
   non-empty, else the default byte at `+0x153`.

Fields read, and nothing else:

| offset | width | role |
| ------ | ----- | ---- |
| `(rdi)+0x00` | 1 byte | flag byte; only the value 1 takes the selector path |
| `+0x100` | 4 bytes | signed selector; read only when the flag byte is 1 |
| `+0x153` | 1 byte | default byte; returned only when the vector is empty |
| `+0x1c8` | 8 bytes | vector begin pointer; its first byte is returned when begin != end |
| `+0x1d0` | 8 bytes | vector end pointer; compared against begin only |

The routine never reads vector bytes past the first, never reads
a size field (emptiness is begin == end, not a length), never
reads the flag holder beyond its first byte, and never reads any
other object offset. All four of its direct jumps land inside
itself, so it has no tail jump out and no landing-pad block; the
bytes after the FDE range (`0x5d51c64..0x5d51c70`) are int3
padding, not a landing-pad block, and the next FDE is a separate
routine.

## Consumers (site-only)

The census finds exactly three direct call sites, no tail jumps:

- `0x5de3490`, inside caller `0x5de3340..0x5de404e`. The
  argument registers are set earlier in the caller; only the site
  and FDE range are claimed.
- `0x5de553e`, inside caller `0x5de44c0..0x5de7ed0`. Same: only
  the site and FDE range are claimed.
- `0x5e674a2`, inside caller `0x5e666a0..0x5e68ceb`. Here the
  argument setup is visible just before the call: `rdi` is the
  caller field at base `+0x5a8` (`lea 0x5a8(%rbx), %rdi`) and
  `rsi` is a caller stack temporary (`lea -0x10f0(%rbp), %rax;
  mov %rax, %rsi`). Caller semantics beyond the site and FDE
  range are not claimed.

## NOT claimed

What the flag, the selector, the vector, or the default byte
denote; what the callers do with the returned byte; behaviour on
dangling pointers, a vector whose end is before its begin, or a
flag-holder pointer that is null (the routine reads `(rdi)`
unconditionally, so the model raises on a null source, stated
openly); the meaning of the neighbouring routines, including the
`0x5d51c70` release routine mapped in the previous cycle.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d51c20 --stop-address=0x5d51c64 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (branches, reads, census).
- `frames.txt`: FDE lines for the routine and its three caller
  functions. `callers.tsv`: the three direct call sites with their
  smallest enclosing caller FDE ranges. `relocations.txt` is empty:
  no relocation record mentions this routine.
- Census method: the external call census uses the exhaustive
  executable-segment E8/E9 scan with objdump confirmation per
  candidate; all three sites were confirmed as real
  `call 0x5d51c20` instructions by direct dumps. The routine's own
  control transfers are classified from one linear disassembly of
  the whole routine range (true instruction starts only).
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and
  the model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/byte_getter_51c20_115.py`, tested by
  `tests/test_byte_getter_51c20_115.py`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5d51c20 --stop-address=0x5d51c64 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests
- Input: `work/hl-node-115.bin`, SHA-256 as above; no execution of
  the target binary, no network, no side effects beyond writing
  the packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`) and the model tests are
run before submission and must print ALL CHECKS PASSED and the
model check count. Repository-wide gates (`make verify`,
`make test`, `make catalogue-check`) are not claimed here: they
cover the whole tree, and their baseline on this VM is affected
by missing LFS material and the absence of cargo/rustc, which
are pre-existing environment limits, not results of this change.
The next question is: what do the three callers do with the
returned byte, and what object owns the `+0x5a8` field passed at
site `0x5e674a2`?
