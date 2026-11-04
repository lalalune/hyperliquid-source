# RE-001-node115-lu-classmin: the single-shot class-search caller

- Component ID: lu class-minimum consumer
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all exhibited bytes and call
  targets; inference for the take/give-back accounting direction
  (derived from the helpers' instruction sequences, cited by
  address); unresolved for the items listed at the end
- Scope included and excluded: included is the single-shot
  caller FDE `0x63b8820..0x63b8d85` main path (guards, fetch,
  class search, take, stamp, build, give-back, return) with six
  exhibits totalling 343 bytes. Excluded (cited by address only):
  the take helper `0x63d8e70`, the give-back helper `0x63d9070`,
  the class-search helper `0x63d9340`, the consumer `0x63b9690`,
  the item fetch `0x63b5840`, the value compute `0x63ba680`,
  the predicate `0x63ae2b0`, the virtual `*0x128` call, the
  completion helpers, and the loop caller `0x63b81b0` delegation.

## Reproduce

In the worktree root, with the node binary at
`artifacts/node/115/hl-node`:

- `python3 tools/node115_lu_classmin.py` — static verifier, exit 0
- `python3 -m unittest tests.test_node115_lu_classmin` — 10/10
- `make verify` — exit 0 (29 manifests, 473 entries)
- `make catalogue-check` — exit 0
- `make test` — 77 files attempted, 1 failed: the pre-existing
  `test_node115_catalogue` Errno 18 cross-device-link error,
  identical on pristine checkouts, not a packet regression;
  this packet's file [36/77] passes 10/10

No execution of the node binary at any point. Tool: system
`objdump` (ELF disassembly) and Python 3 (byte reads, SHA-256,
rel32 arithmetic). Coordinate system: `.text` file offset =
VA − 0x1000; `.rela.dyn` at file offset `0x6be8`, 60,723 entries.

## Evidence

FDE bounds confirmed by `.eh_frame`
(`pc=0x63b8820..0x63b8d85`); the following byte at `0x63b8d85`
is `int3` padding and the next function starts with `endbr64` at
`0x63b8d90`. Single `ret` at `0x63b889f`, reached via the
epilogue jump from `0x63b8ad5` and the early-return path at
`0x63b887d`.

Exhibit bytes (all verified against the binary):

- `cm_entry` (`0x63b8820..0x63b8874`, 84 B, strict 20):
  `endbr64`, pushes, stack-argument load, canary, `cmp $0x1000,%rcx`
  / `ja`, `test %r8b,%r8b` / `jne`, `[rsp+0x48] := 0`,
  `rbx := rsi`, `r13 := rdx`.
- `cm_fetch` (`0x63b88de..0x63b8923`, 69 B, strict 16):
  `lea 0x128(%rbx),%rsi`, item-fetch call `0x63b5840`, pair
  save, NULL test / `je`, `lea 0x140(%rbx),%rbp`,
  class-search call `0x63d9340` at `0x63b8918`, return save to
  `r14`, NULL test / `je`.
- `cm_take` (`0x63b8929..0x63b895c`, 51 B, strict 12): take call
  `0x63d8e70` at `0x63b892f`, `[r14+0x68]` test, counter consume
  at `[context+0x15e0]` with stamp store `mov %rcx,0x8(%r14)`
  at `0x63b894d`, value-compute call `0x63ba680` at `0x63b8957`.
- `cm_build` (`0x63b895c..0x63b89c0`, 100 B, strict 22):
  entry-field rebuild (page-bit mask `0xffffeffff0000fff`,
  constant `0xe806000`, `[r15+8] := r9`, `[r15+0x20] := [r14+8]`,
  `[r15+0x50] := 0`, embed store `mov %r14,0x18(%r15)` at
  `0x63b89bc`).
- `cm_give` (`0x63b8a3d..0x63b8a5a`, 29 B, strict 7):
  give-back call `0x63d9070` at `0x63b8a43`, saved-pair write
  to `[r15+0x28]`, splice-guard load and test.
- `cm_ret` (`0x63b8ad0..0x63b8ada`, 10 B, strict 2):
  `mov 0x48(%rsp),%rax`, `jmp` to the epilogue.

Cited helper behaviour (read from their disassembly, bytes not
claimed here):

- Take helper `0x63d8e70`: sets `node+0x23 := 1`; if
  `node+0x68 == 0` takes the zero-size path (slot-entry decrement
  at `record+0x1050` sub-slot); if `== 0x200` the huge path
  (`record+0x1020`); otherwise derives the class index from
  `node+0x60 << 12` via `0x63e8bf0` and stores `(count-1,
  bytes+1)` into the `record+0x420 + index*48` entry with matching
  record-total adjustments — the free-side decrement.
- Give-back helper `0x63d9070`: clears `node+0x23 := 0`,
  increments the same entry and record totals (net over the pair:
  the node's size moves into entry field 1 and record `+0x410`),
  then moves the node in the `+0x50`/`+0x58` list rooted at
  `[record+0x1498]` according to the `+0x14`/`+0x20` flags
  (insert at head, splice out, or head-removal).
- Class-search helper `0x63d9340` (#230): cited call site only.
- Loop caller `0x63b81b0`: called twice in the second phase;
  not decoded here.

Census: whole-`.text` byte scan + per-site disassembly; 0 direct
E8, 0 E9, 1 LEA (`0x63b90f5`, a neighbouring function loading
this FDE's address as a callback argument), 0 `.rela.dyn`
addend hits (60,723 entries). Internal direct calls in the FDE
(objdump mnemonic lines): trylock, item fetch, class search,
take, value compute, predicate, virtual call, give-back,
completion pair, loop caller (twice), unlock, contention helper,
stack-check-fail. All direct branch targets lie inside the FDE.

Disjointness: this FDE overlaps no claimed range from packets
#183–#231 (class-search #230, class-merge #231, finder #226,
slot-head #225, release #224, size-rep #227, table-fill #228,
descbuild #229, and the cited loop caller A); the class-search
tail-call site and the consumer FDE are cited, not claimed.

## Implementation and comparison

Not yet implemented/measured. This packet is evidence only; no
reconstruction code is proposed for the caller.

## Results and limitations

Machine-readable metrics: 6 exhibits, 343 bytes, 79 strict
instructions, FDE 1381 bytes, census 0 E8 / 0 E9 / 1 LEA / 0 GOT,
MANIFEST 17/17, verifier exit 0, unit tests 10/10, `make verify`
exit 0 (29 manifests, 473 entries), `make catalogue-check` exit 0,
`make test` [77/77] with
only the pre-existing catalogue Errno 18 failure.

What remains unknown is listed in README.md (item/compute
identities, wake predicate, completion-byte protocol, loop-caller
delegation, in-use-list identity, splice-block purpose). No gate
is requested beyond the packet's own verification.

Next question: decode the loop caller `0x63b81b0` end to end —
how it iterates items, whether each iteration consumes one class
minimum the same way, and what its count argument and entry slot
do.
