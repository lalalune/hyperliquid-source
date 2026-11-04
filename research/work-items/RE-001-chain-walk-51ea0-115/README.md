# RE-001: node #115 guarded chain walk 0x5d51ea0

## Bounded question

What does routine `0x5d51ea0` (FDE `0x5d51ea0..0x5d51feb`,
427 bytes) do with its destination and source arguments, and
which virtual method does it end up calling?

## Answer, pinned to the target

The routine takes two arguments -- a destination pointer in
`rdi` and a source object pointer in `rsi` -- and returns the
destination pointer. End to end, in order:

1. **Gate.** Read the qwords at source `+0x418` and `+0x420`.
   When BOTH are zero, the destination is zeroed and the
   routine returns at once: bytes 0-5 (a dword at `+0x00` and a
   word at `+0x04`) and bytes 8-15 (a qword at `+0x08`) are
   written zero; bytes 6-7 are never written. No setup call,
   no walk, no virtual call, no temp disposal happens on this
   path, and the stack temp at `rsp` is never read.
2. **Setup** (only when the gate passes, i.e. either field is
   non-zero). Call `0x60a1500` with (source `+0x330`, source),
   then call `0x603d410` with (the stack temp slot at `rsp`,
   the first call's result). Both callees are opaque here;
   what is pinned is the argument lists and order. The second
   call fills a 32-byte string-shaped temp at `rsp` (pointer
   at `+0x00`, capacity-or-inline-buffer at `+0x10`).
3. **Chain walk.** Start from the node at source `+0x318` and
   follow each node's `+0x48` link. Each node's vtable slot
   at `+0x118` is compared with the previous node's slot,
   where the first node is compared with the sentinel qword
   at `0x64ed1b8` (loaded rip-relative at `0x5d51f05`). The
   first node whose slot differs from its predecessor's is
   called through that slot with (destination, node, temp
   slot). If the first four nodes all carry the same slot,
   the fifth node is called through its slot unconditionally.
   At most five nodes are visited; the walk has no other exit.
4. **Temp disposal**, by the std::string SSO rule: if the temp
   pointer differs from the temp's own `+0x10` slot address
   (heap form), delete it with size capacity `+ 1`, capacity
   read from the `+0x10` slot; inline form frees nothing. The
   temp size field at `+0x08` is never read by this routine.

The routine's own control transfers are exactly four direct
calls (the two setup calls, the temp operator delete, and the
stack-canary failure call), one direct tail jump out (the
landing pad's jump to the cleanup block), and three indirect
calls (the three virtual slot call sites at `0x5d51f60`,
`0x5d51fc6` and `0x5d51fd6`); it has no indirect tail jump.
Its landing-pad entry at `0x5d51fdf` lies inside the FDE
range, saves the incoming value in `rbx`, and jumps to the
cleanup block at `0x5d51e6e..0x5d51e93`, which disposes the
temp string (std::string `_M_dispose` on the temp slot) and
resumes unwinding. It is recorded, not modelled as a normal
return. The single byte after the FDE range (`0x5d51feb`) is
`int3` padding before the next FDE at `0x5d51fec`; the `int3`
padding at `0x5d51e93..0x5d51ea0` follows the cleanup block.

## Consumers (site-only)

The census finds exactly one direct call site, no tail jumps:

- `0x5e631de`, inside caller `0x5e62c50..0x5e65462`, which
  moves its `rbx` into `rdi` and a caller stack value into
  `rsi` before the call.

Only the site and FDE range are claimed; caller argument
setup beyond those two moves is not pinned here.

## NOT claimed

What the setup callees compute, what the source fields, the
nodes, the vtable slot, or the sentinel denote, caller
semantics beyond the site and FDE range, or behaviour on
dangling pointers or a null source, head node, or chain link
(the routine reads them unconditionally, so the model raises
on nulls, stated openly). The neighbouring routines are not
part of this claim.

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
- `cleanup.txt`: the landing-pad cleanup block, verbatim,
  from the same generator.
- `frames.txt`: the routine, cleanup-block, and caller FDE
  lines from a fresh readelf frame dump.
- `callers.tsv`: the one direct call site from the census.
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

    python3 research/work-items/RE-001-chain-walk-51ea0-115/export_excerpts.py
    python3 research/work-items/RE-001-chain-walk-51ea0-115/census.py
    python3 research/work-items/RE-001-chain-walk-51ea0-115/verify.py
    python3 tests/test_chain_walk_51ea0_115.py

Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed here: the baseline
is affected by missing LFS material and by the absence of
cargo/rustc on this VM, which predates this change.

## Concrete next step

Decompose the single caller `0x5e62c50..0x5e65462` around
the call site (what its `rbx` denotes, what follows the
call), and decompose the setup callees `0x60a1500` and
`0x603d410` that fill the temp the virtual call receives.
