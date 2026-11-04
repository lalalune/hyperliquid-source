# RE-001: node #115 threshold flag clear 0x5d52cf0

## Bounded question

What does routine `0x5d52cf0` (FDE `0x5d52cf0..0x5d52d6c`,
124 bytes) do with its owner argument and threshold, and what
does it broadcast on when it finishes?

## Answer, pinned to the target

The routine takes two arguments -- an owner pointer in `rdi`
and a threshold in `rsi` -- and returns through a tail jump,
not a `ret`. End to end, in order:

1. **Acquire.** Call `0x60d5390` with owner `+0x9c8`. That
   callee is a no-op stub: its whole body is `endbr64; ret`
   (FDE `0x60d5390..0x60d5395`), so the call returns at once
   and changes nothing observable. It is pinned, not assumed:
   the stub is shipped verbatim as `acquire.txt`.
2. **Scan.** Walk the owner's entry sequence, which is chunked
   in 0x200-byte blocks of 0x20-byte entries. The walk state is
   read from the owner: cursor at `+0xb30`, current chunk end
   at `+0xb40`, end cursor at `+0xb50`, and the current
   chunk's map slot at `+0xb48` (the next chunk is taken from
   the following slot, +8 at a time). For each entry, in order:
   - if the cursor equals the end cursor, stop;
   - if the entry's first qword (its key) is unsigned-greater
     than the threshold, stop at once -- later entries, in this
     and later chunks, are untouched. (AT&T `cmp (%rax),%rbx`
     at `0x5d52d35` computes rbx minus the key, so the `jb` at
     `0x5d52d38` exits exactly when the threshold is
     unsigned-less than the key; a key equal to the threshold
     is cleared, not stopped on. An earlier revision of this
     packet had the direction inverted; slopbot's limited
     review of the PR caught it and this revision corrects
     the model, the tests, and the records to match the bytes);
   - otherwise write 0 to the byte at entry `+0x10` and advance
     the cursor by 0x20;
   - when the cursor reaches the current chunk end, take the
     next chunk base from the next map slot, set the chunk end
     to base + 0x200, and stop if that base equals the end
     cursor, else continue with the new chunk's first entry.
   The field at `+0xb38` (between cursor and chunk end) is
   never read, and no entry byte other than `+0x10` is written.
   No owner field is written anywhere in the routine.
3. **Broadcast.** Tail-jump to `0x60d57c0` with owner `+0xb70`.
   That callee's first action is `pthread_cond_broadcast` on
   its argument (call at `0x60d57da`), so the `+0xb70` member
   is broadcast on; the callee's internal error path (fprintf
   + abort on an unexpected broadcast result) is callee-internal
   and is recorded, not modelled. The whole callee is shipped
   verbatim as `broadcast.txt`.

The routine's own control transfers are exactly one direct call
(the acquire stub at `0x5d52d07`), one direct tail jump out
(the broadcast jump at `0x5d52d67`), and no indirect transfer
of any kind. It has no landing-pad block; the four bytes after
the FDE range (`0x5d52d6c..0x5d52d70`) are `int3` padding
before the next FDE at `0x5d52d70`.

## Consumers (site-only)

The census finds exactly four direct call sites, no tail jumps:

- `0x5d7f8f6`, inside caller `0x5d7f3b0..0x5d7fb40`, which
  moves its `r12` into `rsi` and its `rbp` into `rdi` before
  the call;
- `0x5ddd633`, inside caller `0x5ddd080..0x5ddd673`, which
  moves its `r12` into `rdi` before the call (its `rsi` setup
  lies outside the excerpt window and is not pinned);
- `0x5e90366`, inside caller `0x5e8ef90..0x5e904bd`, which
  moves a caller stack value at `-0x678(%rbp)` into `rdi`
  before the call (its `rsi` setup is not pinned);
- `0x5e939c0`, inside caller `0x5e91ed0..0x5e9406a`, which
  moves its `r14` into `rdi` before the call (its `rsi` setup
  is not pinned).

Only the sites, FDE ranges, and the pinned moves above are
claimed; wider caller semantics are not.

## NOT claimed

What the owner, the entries, the keys, or the `+0x10` flag byte
denote; the order the entries are stored in beyond the
above-threshold stop rule; what the acquire stub or the
broadcast callee do beyond the pinned body and first action
noted above; caller semantics beyond the sites, FDE ranges,
and pinned moves; or behaviour on dangling pointers, a null
owner (the model raises, stated openly), or a map slot list
that runs out at a chunk end (the binary reads the next slot
unchecked; the model raises instead, stated openly). The
deque-shaped reading of the fields (cursor / chunk end / end
cursor / map slot) is an inference from the walk shape,
recorded as such in `records.json`; the model implements the
literal transition rules, not the inferred container type.
The neighbouring routines are not part of this claim.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `export_excerpts.py` from a fresh objdump run. The
  mnemonics in it (including `endbr64`) are genuine
  instructions present in the target binary, not
  placeholders; `verify.py` checks every excerpt instruction
  byte-for-byte against the raw binary.
- `acquire.txt`: the no-op acquire stub, verbatim, from the
  same generator.
- `broadcast.txt`: the tail-jump target, verbatim, from the
  same generator; its broadcast call is at `0x60d57da`.
- `frames.txt`: the routine, acquire-stub, broadcast, and
  caller FDE lines from a fresh readelf frame dump.
- `callers.tsv`: the four direct call sites from the census.
- `relocations.txt`: empty -- no RELATIVE relocation record
  mentions this routine.
- `census.py`: reproduces the census (executable-LOAD-segment
  exhaustive E8/E9 scan with objdump confirmation of each
  candidate, plus the routine's own transfers from one linear
  disassembly).
- `verify.py`: the runnable checker behind ALL CHECKS PASSED
  (digest, provenance, manifest, excerpt regeneration
  byte-for-byte, every excerpt instruction byte-for-byte,
  FDE ranges, census, records, model tests).

## Reproduce

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. From the repository root:

    python3 research/work-items/RE-001-flag-clear-52cf0-115/export_excerpts.py
    python3 research/work-items/RE-001-flag-clear-52cf0-115/census.py
    python3 research/work-items/RE-001-flag-clear-52cf0-115/verify.py
    python3 tests/test_flag_clear_52cf0_115.py

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline
is affected by missing LFS material and by this VM having no
cargo/rustc, so only the packet's own checker and the model
tests are claimed green. The next step is the four callers'
wider behaviour around this routine, and what the `+0x10`
flag byte gates downstream.
