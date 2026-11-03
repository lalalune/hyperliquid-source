# RE-001: node #115 composite object release 0x5d51c70

## Bounded question

What does routine `0x5d51c70` (FDE `0x5d51c70..0x5d51d05`, 149 bytes)
release when it is called on an object, in what order, and what does
it leave alone?

## Answer, pinned to the target

The routine releases one composite object, pointed to by `rdi`, in
four phases. It reads exactly five object fields and writes none of
them, and it never frees the object itself:

| offset | width | role |
| ------ | ----- | ---- |
| `+0x00` | 8 bytes | head member pointer, released last |
| `+0x08` | 8 bytes | vector begin pointer |
| `+0x10` | 8 bytes | vector end pointer |
| `+0x18` | 8 bytes | vector capacity-end pointer |
| `+0x20` | 8 bytes | single member pointer, released first |

The sequence, in order:

1. If the pointer at `+0x20` is non-null, release it: the routine
   loads that member's first qword (its vtable pointer) and calls
   the function pointer at vtable offset `+0x8` with the member
   pointer as its argument. A null member is skipped.
2. Walk the vector from `+0x08` (begin) to `+0x10` (end), one
   8-byte element at a time, in order. Each non-null element is
   released the same way (vtable slot `+0x8`, element pointer as
   argument); null slots are skipped, not released.
3. If the begin pointer at `+0x08` is non-null, delete the vector
   buffer with operator `delete` (entry point `0x63f0d80`), with
   size equal to the capacity end at `+0x18` minus begin, in
   bytes. If begin is null, no delete happens, even when the loop
   above was empty; if begin is non-null but the vector is empty,
   the delete still runs with the capacity size.
4. If the pointer at `+0x00` is non-null, release it the same way
   -- but via an indirect tail jump to vtable slot `+0x8`, so
   that release returns directly to this routine's caller. If it
   is null, the routine simply returns.

The bytes after the FDE range (`0x5d51d05..0x5d51d10`) are int3
padding, not a landing-pad block, and the next FDE is a separate
routine.

## Consumers (site-only)

The census finds exactly one direct call site, `0x5d84b1f`, inside
the caller function `0x5d8479c..0x5d85475`. At that site the
argument is the caller's object field at base `+0xd08`
(`lea 0xd08(%rbx), %rdi` immediately before the call). Caller
semantics beyond the site and FDE range are not claimed.

## NOT claimed

What the object, its head, its single member, or its vector
elements denote; what the slot `+0x8` release functions do
internally (the binary pins only that they are invoked, with the
member pointer as argument, in this order); the object's size
beyond the five fields read; caller semantics beyond the site and
FDE range; behaviour on dangling pointers, a vector whose end is
before its begin, or a capacity end before begin (the model raises
on malformed inputs, stated openly); the release functions'
internals beyond the slot called.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d51c70 --stop-address=0x5d51d05 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (reads, order, census).
- `frames.txt`: FDE lines for the routine and its single caller
  function. `callers.tsv`: the one direct call site with its
  smallest enclosing caller FDE range. `relocations.txt` is empty:
  no relocation record mentions this routine.
- Census method note: the routine's own control transfers are
  classified from one linear disassembly of the whole routine
  range (true instruction starts only). A raw byte scan of the
  range misreports the `0xe9` operand byte of the jne at
  `0x5d51cb5` as a tail jump at `0x5d51cb6`; that site is not a
  real instruction and is not counted. The external call census
  still uses the exhaustive executable-segment E8/E9 scan with
  objdump confirmation per candidate, and its one site
  (`0x5d84b1f`) was confirmed as a real `call 0x5d51c70`
  instruction by a direct dump.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and
  the model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/object_release_51c70_115.py`, tested by
  `tests/test_object_release_51c70_115.py`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5d51c70 --stop-address=0x5d51d05 work/hl-node-115.bin`
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
The next question is: what object owns the `+0xd08` field passed
at the single call site `0x5d84b1f`, and what do its `+0x00` and
`+0x20` members denote in that caller?
