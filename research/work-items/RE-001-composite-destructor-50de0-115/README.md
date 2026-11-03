# RE-001: node #115 composite destructor 0x5d50de0

## Bounded question

What does routine `0x5d50de0` (FDE `0x5d50de0..0x5d51002`, 546 bytes)
destroy when it is called on an object, in what order, and what does
it leave alone?

## Answer, pinned to the target

The routine destroys one composite object, pointed to by `rdi`, in
four phases. It reads exactly eight object fields, writes only the
four container-state fields listed below, and never frees the object
itself or any chunk buffer:

| offset | width | role |
| ------ | ----- | ---- |
| `+0x00` | 8 bytes | pointer-vector first-chunk count (phase 4 bound addend; zeroed at the end) |
| `+0x48` | 8 bytes | pointer-vector first-chunk buffer pointer |
| `+0x50` | 8 bytes | pointer-vector second-chunk begin pointer (also the reset target for `+0x58`) |
| `+0x58` | 8 bytes | pointer-vector second-chunk end pointer (reset to `+0x50` at the end) |
| `+0x68` | 8 bytes | element-vector first-chunk count (phase 1 bound addend; drained to zero by phase 2) |
| `+0x1f0` | 8 bytes | element-vector first-chunk buffer pointer |
| `+0x1f8` | 8 bytes | element-vector second-chunk begin pointer (also the reset target for `+0x200`) |
| `+0x200` | 8 bytes | element-vector second-chunk end pointer (reset to `+0x1f8` after phase 3) |

The sequence, in order:

1. Virtual-call walk over the whole element vector. The iteration
   count is the second-chunk element count plus the `+0x68` count,
   where the second-chunk element count is (`+0x200` minus `+0x1f8`)
   divided by `0x30`. (The division is computed as a shift by 4
   followed by a multiply with `0xaaaaaaaaaaaaaaab`, the modular
   inverse of 3: exact because the byte size is a multiple of
   `0x30`.) Element `i` comes from the first chunk when `i <= 7`
   and from the second chunk at index `i - 8` otherwise. Each
   element is `0x30` bytes: a string at `+0x00` (pointer `+0x00`,
   size `+0x08` never read, capacity-or-inline-buffer `+0x10`), 8
   unread bytes at `+0x20`, and a pointer at `+0x28` to a struct
   whose `+0x140`/`+0x148` delimit a `0x10`-stride list. For each
   list entry, in order, the entry's first qword is its object
   pointer; the function pointer at vtable slot `+0x100` is loaded,
   and when it differs from the sentinel `0x5d48450` it is called
   with (entry object, element address). Sentinel entries are
   skipped, not called.
2. First-chunk string disposal, backwards. The `+0x68` count is
   decremented to zero, one element at a time from the last to the
   first; each element's string is freed with operator `delete`
   (entry point `0x63f0d80`) with size capacity + 1 when its pointer
   differs from its own `+0x10` slot address (heap string); a
   pointer equal to that slot address is an inline (SSO) string and
   nothing is freed.
3. Second-chunk string disposal, forwards. Each second-chunk
   element's string is freed the same way (heap only, size
   capacity + 1), in order; then the `+0x200` end pointer is reset
   to the `+0x1f8` begin pointer. The second-chunk buffer itself is
   not freed.
4. Pointer-vector teardown, forwards. The iteration count is the
   second-chunk pointer count plus the qword at `+0x00`, where the
   second-chunk pointer count is (`+0x58` minus `+0x50`) divided by
   8. Pointer `i` comes from the first chunk (buffer `+0x48`) when
   `i <= 7` and from the second chunk at index `i - 8` otherwise.
   Each non-null pointer is destroyed by the callee at `0x5d8d820`
   and then freed with operator `delete` with size `0x290`. Null
   slots are skipped. Finally the `+0x00` qword is zeroed (when
   non-zero) and the `+0x58` end pointer is reset to the `+0x50`
   begin pointer (when they differ). The chunk buffers are not
   freed.

The bytes after the FDE range (`0x5d51002..0x5d51010`) are int3
padding, not a landing-pad block, and the next FDE is a separate
routine.

Well-formedness note, stated openly: the index rule (first chunk
for indices 0..7, second chunk from index 8) is consistent with the
bounds only when the first-chunk count equals 8 whenever the second
chunk is non-empty, or equals the total when the second chunk is
empty. The model implements the binary's literal rule and raises on
walks that would read past a provided chunk; it does not smooth
over that assumption.

## Consumers (site-only)

The census finds exactly eleven direct call sites, in ten caller
functions. Caller semantics beyond the sites and FDE ranges are not
claimed:

| site | caller FDE |
| ---- | ---------- |
| `0x5d519e1` | `0x5d519d0..0x5d51aaf` |
| `0x5d6a3ce` | `0x5d69a00..0x5d6a6d9` |
| `0x5d6b749` | `0x5d6b530..0x5d6b7d4` |
| `0x5d7223d` | `0x5d71fe0..0x5d72e50` |
| `0x5d7390b` | `0x5d72ed0..0x5d73e60` |
| `0x5d77c02` | `0x5d77770..0x5d7833f` |
| `0x5d781bf` | `0x5d77770..0x5d7833f` |
| `0x5d836cc` | `0x5d82240..0x5d83d9a` |
| `0x5dedd9b` | `0x5decc70..0x5dedffa` |
| `0x5e64560` | `0x5e62c50..0x5e65462` |
| `0x5e81b1e` | `0x5e80ea0..0x5e81ec0` |

## NOT claimed

What the object, its element vector, its pointer vector, or the
destroyed targets denote; what the `0x5d8d820` destroy callee or
any vtable slot `+0x100` function does internally (the binary pins
only that they are invoked, with the arguments above, in this
order); the meaning of the `+0x20` element field or the element
string sizes beyond the capacity rule; the object's size beyond
the eight fields read; caller semantics beyond the sites and FDE
ranges; behaviour on dangling pointers, inconsistent chunk counts,
or a partially constructed object (the model raises on malformed
inputs, stated openly).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d50de0 --stop-address=0x5d51002 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (reads, phases, census).
- `frames.txt`: FDE lines for the routine and its ten caller
  functions. `callers.tsv`: the eleven direct call sites with
  their smallest enclosing caller FDE ranges. `relocations.txt`
  is empty: no relocation record mentions this routine.
- Census method note: the routine's own control transfers are
  classified from one linear disassembly of the whole routine
  range (true instruction starts only); the five direct jumps
  inside the range all land inside it, so there is no direct tail
  jump out. The external call census uses the exhaustive
  executable-segment E8/E9 scan with objdump confirmation per
  candidate; no candidate was rejected.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and
  the model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/composite_destructor_50de0_115.py`, tested by
  `tests/test_composite_destructor_50de0_115.py`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x5d50de0 --stop-address=0x5d51002 work/hl-node-115.bin`
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
The next question is: what do the two chunked vectors denote in
the ten caller functions, and what does the `0x5d8d820` destroy
callee do to a `0x290`-byte target?
