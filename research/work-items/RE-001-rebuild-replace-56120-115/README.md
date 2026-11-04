# RE-001: rebuild-and-replace routine 0x5d56120 (node #115)

## Bounded question

What does the routine at `0x5d56120` do end to end: which fields of the
destination struct does it rebuild, what fresh object does it install, what
happens to the previously installed object, and which code reaches it?

## Answer (established semantics)

The routine rebuilds a destination struct from two source pairs and installs
a freshly allocated 0x58-byte object, releasing the previously installed
object. In order:

1. Copy the 16-byte source pair A from `(rsi)` to `dest+0x00`. If the copied
   second word (`dest+0x08`) is non-null, increment its packed refcount low
   half (plain increment when the guard byte at `0x64ed290` is nonzero,
   locked increment when it is zero — the same guard rule as the shared
   release helper `0x5d350c0`).
2. Copy the 16-byte source pair B from `(rdx)` to `dest+0x10`. If the copied
   second word (`dest+0x18`) is non-null, increment its refcount the same way.
3. Zero `dest+0x20` (the old subobject view is cleared before install).
4. Allocate a 0x58-byte object with operator new. Its `+0x00` slot is the
   table at `0x64c9830` (`0x64c9820 + 0x10`); its `+0x08` slot is the qword
   loaded from `0x459b20`, whose value in this binary is `0x100000001` —
   the packed refcount sentinel (low half 1, high half 1) that the release
   helper destroys in a single release.
5. Initialize the new object's `+0x10` subobject with `0x5fe7210` (see
   below), then overwrite that subobject's table slot with the derived
   table `0x64d08a8` — the same derived table whose destructor pair
   (`0x5d55970` / `0x5d559c0`) the RE-001 derived-destructor packet pins.
6. Copy `dest+0x10` (16 bytes, the B pair) to `new+0x40`, and increment the
   copied second word (`new+0x48`, the same target as `dest+0x18`) a second
   time, so the new object holds its own reference to it.
7. Call the lazy singleton accessor `0x5fe2680` and store `[singleton]` at
   `new+0x50` (the singleton's first slot is the address `first+0x10`, where
   `first` is the singleton's 0x10-byte record; see below).
8. Install: `dest+0x20 = new+0x10` (a non-owning view of the new subobject),
   `dest+0x28 = new`. The previous `dest+0x28` value, if non-null, is passed
   to the shared release helper `0x5d350c0` by tail jump; if it was null the
   routine returns. The previous `dest+0x20` view is overwritten with no
   release call of its own — consistent with it being a non-owning alias of
   the previous owner's `+0x10` subobject, which the owner's destruction
   covers. This aliasing is an inference, recorded as such.

## The subobject initializer 0x5fe7210 (216 bytes, pinned whole)

Takes `(new+0x10, dest)`. It first calls the base constructor `0x5fe7080`
(48 bytes, pinned whole): table slot `0x64cf008` (`0x64ceff8 + 0x10`) and
`+0x08` / `+0x10` / `+0x18` zeroed. It then overwrites the table slot with
the middle table `0x64cf200` (the same middle table the derived destructor
restores during teardown), copies `dest+0x00` (16 bytes, the A pair) to
`subobject+0x20`, and increments the copied second word
(`subobject+0x28`, the same target as `dest+0x08`) if non-null — the
subobject's own reference to A. Finally it calls `0x6099ce0` with
`(subobject, stack_string, subobject+0x20, global 0x65051e0)`, where
`stack_string` is an empty short-string object (pointer to its own inline
buffer, length 0); after the call, a heap-allocated result is sized-freed
with size capacity + 1. What `0x6099ce0` computes inside the subobject is
NOT pinned here — call shape only, listed under unknowns. The routine has a
stack canary and one landing-pad fragment that forwards to `0x5fe71cc`.

## The lazy singleton accessor 0x5fe2680 (214 bytes, pinned whole)

Returns a lazily initialized singleton record. If the guard byte at
`0x6504c98` is nonzero, it returns the cached pointer at `0x6504ca0`.
Otherwise it acquires the guard, allocates a 0x10-byte record A
(`+0x00 = 0x64ced00`, `+0x08 = [0x459b20] = 0x100000001`) and a 0x30-byte
record B (`+0x00 = A+0x10`, `+0x08 = A`, `+0x18` / `+0x20` / `+0x28 = 0`;
`B+0x10` is not written on this path), stores B at `0x6504ca0`, releases
the guard and returns B. So `new+0x50 = [B] = B+0x00 = A+0x10`, the address
of the slot inside A that holds `0x64ce930`.

## Exception cleanup (three landing pads, code pinned whole in main.txt)

The main routine's FDE range contains three landing-pad fragments after the
normal return. Their code is:

- Pad at `0x5d5624f`: full cleanup — release `new+0x48`, reset the
  subobject table slot to the middle table `0x64cf200`, release
  `new+0x38` (the subobject's A reference), call the base destructor
  `0x5fe70b0` on the subobject, sized-delete the new object (0x58), then
  fall through to the resume path.
- Pad at `0x5d56261`: delete-only — sized-delete the new object (0x58),
  then fall through to the resume path.
- Pad at `0x5d56258`: resume-only — straight to the resume path.
- Resume path at `0x5d562ad`: release `dest+0x28`, `dest+0x18`,
  `dest+0x08` through the helper when non-null, then `_Unwind_Resume`.

Which protected range each pad covers is NOT established from the excerpt
alone (the LSDA was not decoded here) and is recorded as unknown; the pad
bodies themselves are verbatim.

## Consumers

Exactly 7 direct calls, 0 tail jumps, 0 stored references (executable-LOAD
E8/E9 scan with objdump confirmation, reproduced by `census.py` and re-run
inside `verify.py`):

| site | caller FDE |
| --- | --- |
| 0x5d5f045 | 0x5d5ef80..0x5d5f414 |
| 0x5d5f339 | 0x5d5ef80..0x5d5f414 |
| 0x5d5f36b | 0x5d5ef80..0x5d5f414 |
| 0x5d7797f | 0x5d77770..0x5d7833f |
| 0x5d81971 | 0x5d81820..0x5d8205c |
| 0x5d85637 | 0x5d85480..0x5d878e2 |
| 0x5d866fe | 0x5d85480..0x5d878e2 |

The routine is reached only by code, never by data.

## Relation to neighbouring packets

This routine constructs the very object class whose destructor pair the
RE-001 derived-destructor packet (`0x5d55970` / `0x5d559c0`) pins: same
derived table `0x64d08a8`, same middle table `0x64cf200`, same base
destructor `0x5fe70b0`, same release helper `0x5d350c0`, same packed
sentinel `0x100000001`. The constructor side and the destructor side now
match field for field (the destructor releases `+0x38` and `+0x28` of the
subobject view — the A references this routine installs twice over, once
for the destination and once for the subobject).

## Unknowns (not filled in)

- Class and field source names; what the destination struct represents.
- What `0x6099ce0` computes inside the subobject (call shape only).
- Which protected range each landing pad covers (LSDA not decoded).
- What the singleton records A and B represent, and what `B+0x10`
  (unwritten on the init path) holds after later use.
- Why the destination keeps both a `+0x20` view and a `+0x28` owner for the
  same object (aliasing inference above, not proven).
- The callers' argument values at the 7 call sites (not traced here).

## Evidence

- `main.txt`, `init.txt`, `ctor.txt`, `singleton.txt`: whole-function
  verbatim objdump excerpts. Regenerate with:
  `objdump -d --start-address=0x5d56120 --stop-address=0x5d562df work/hl-node-115.bin`
  `objdump -d --start-address=0x5fe7210 --stop-address=0x5fe72e8 work/hl-node-115.bin`
  `objdump -d --start-address=0x5fe7080 --stop-address=0x5fe70ab work/hl-node-115.bin`
  `objdump -d --start-address=0x5fe2680 --stop-address=0x5fe2756 work/hl-node-115.bin`
  Headers are normalized to the bare binary name only. The tokens that look
  like short words in the excerpts (for example `endbr64`) are genuine
  instructions present in the target binary, not placeholders.
- `frames.txt`: the FDE lines for the four excerpted routines, the release
  helper, the base destructor, and the four distinct caller functions.
- `callers.tsv`: the 7 confirmed call sites with their caller FDEs.
- `relocations.txt`: empty — no stored reference to the routine.
- `records.json`: semantic records only (field maps, event order, caller
  domains, singleton construction, unknowns). No per-step token list.
- `verify.py`: packet checker (digest, provenance, manifest, excerpt
  regeneration byte-for-byte, excerpt bytes vs the raw binary, FDE lines,
  census, relocations, records shape, model spot checks, full test module).
- `census.py`, `export_excerpts.py`: the scripts that produced the census
  and the excerpts, committed in the packet.

## Artifact binding

Node #115 binary `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
as listed in `provenance/artifacts.json`.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. All evidence above
is static objdump/readelf analysis of the materialized binary plus a Python
model of the established semantics. No Rust reconstruction is claimed.
