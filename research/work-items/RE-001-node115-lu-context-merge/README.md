# RE-001-node115-lu-context-merge

## Question

Packet #248's next question: what sits next to the context reset in the
call graph — the neighbour FDE `0x63d8b20..0x63d8e67`, immediately after
the reset FDE, which ends exactly at `0x63d8b20`.

## Answer

`0x63d8b20(dst, src)` is the lu context **merge**: an element-wise
qword add of a source context into a destination context over
`+0x0..+0xc60` (3168 bytes, 396 qwords), with no other effect. It reads
no flag byte, writes no block key, and calls nothing. Its only known
callers are two small FDEs at `0x63b9180` and `0x63b91e0` (cited only),
and both callers extend the merge with the same 32-byte tail pattern
(src `+0xc60`/`+0xc70` pairs added into dst `+0xc60`/`+0xc70`), so the
full add on both caller paths is `+0x0..+0xc80` (400 qwords).

## Entry contract

- `rdi` = destination object (moved to `rax`, kept live).
- `rsi` = source object (moved to `rcx`, kept live).
- No pushes, no stack use, no other argument is read.
- No return value is established by these bytes: the single `ret` path
  returns with `rax` holding `dst + 0xc00` (the loop's end pointer,
  incidentally), not as a set result. Nothing here claims a caller uses
  it.

## Body, in program order

1. `endbr64`; `rcx := rsi`; `rax := rdi`.
2. Scalar tail first (straight-line, before the loop): 12 qwords at
   `src + 0xc00`, `+0xc08`, `+0xc10`, `+0xc18`, `+0xc20`, `+0xc28`,
   `+0xc30`, `+0xc38`, `+0xc40`, `+0xc48`, `+0xc50`, `+0xc58` are
   each loaded and added into the same offset of `dst`. The loop-end
   pointer `r10 := src + 0xc00` is computed in the middle of this
   sequence (`lea 0xc00(%rcx),%r10` at `0x63d8b8c`).
3. `nopl 0x0(%rax)` (7 bytes alignment padding) at `0x63d8bd9`.
4. Loop head at `0x63d8be0`, 8 iterations of a 384-byte chunk:
   - `movdqu 0x20(%rcx),%xmm4` and `movdqu 0x10(%rcx),%xmm1`
     load the chunk's second and first pairs before the advance.
   - `add $0x180,%rcx`; `add $0x180,%rax` advance both pointers.
   - The remaining 22 pairs are loaded from the advanced `rcx` with
     negative displacements (`-0x180` through `-0x10`, skipping
     `-0x170`/`-0x160`, which are the two pre-advance pairs), each
     pair added (`paddq`) to the matching `dst` pair and stored
     (`movups`) back. All 24 pair offsets are stored exactly once
     per iteration (verifier-checked).
   - `cmp %rcx,%r10; jne 0x63d8be0` exits when `rcx` reaches
     `src + 0xc00`. Since `0xc00 / 0x180 = 8`, the loop runs
     exactly 8 times, covering `+0x0..+0xc00`.
5. `ret` at `0x63d8e66`.

Net effect: `dst[i] += src[i]` for every qword `i` in
`+0x0..+0xc60`. The loop covers `+0x0..+0xc00` (3072 bytes); the
scalar sequence covers `+0xc00..+0xc60` (96 bytes).

## What this decides

- The reset's neighbour is a merge, not an init: where #248 zeroes a
  whole context, this function accumulates one context into another.
  The merged span (`+0x0..+0xc60`) covers the reset's helper region
  (`+0x0..+0x400`), the global triple (`+0x408`/`+0x410`/`+0x418`),
  and the `+0x420`-based counter region through `+0xc60` — but it
  stops short of the slot-pointer table (`+0x1088` base), the
  `+0x1488` bitmap, and the `+0x1498` anchor. So the merge moves
  counter state only; list state is never touched here.
- The caller tail pattern is shared: both known callers add the same
  `+0xc60`/`+0xc70` pair after the call, so the architectural add is
  400 qwords (`+0x0..+0xc80`), with the last 32 bytes handled inline
  by callers rather than inside the merge. The merge FDE itself
  claims only `+0x0..+0xc60`; the tail pairs are caller bytes, cited
  only.
- The two callers differ in what they pass: caller A
  (`0x63b9180..0x63b91d2`) passes its own `(dst, src)` straight
  through and adds `src + 0xc60`/`+0xc70` into `dst + 0xc60`/`+0xc70`;
  caller B (`0x63b91e0..0x63b930c`) passes `(dst = third arg,
  src = object + 0x560)` and adds `object + 0x1628`/`+0x1638` into
  `dst + 0xc60`/`+0xc70`. Caller B's surrounding bookkeeping
  (two `0x63f17b0` calls with failure paths, counter bumps at
  `+0xe8`, `+0xd8`/`+0xe0`, `+0x78`, `+0x68`/`+0x70`, flag bytes
  `+0xa8`/`+0x118`) is not decoded here; only the merge call site,
  its argument setup, and its tail pattern are claimed.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d8b20..0x63d8e67`, 839 bytes); `endbr64` entry;
  `int3` padding `0x63d8b15..0x63d8b20` (11 bytes, after #248's
  reset, which ends at `0x63d8b15`) and `0x63d8e67..0x63d8e70`
  (9 bytes, before the next FDE at `0x63d8e70`, cited only).
  Static analysis only; the binary was never executed.
- 4 exhibits, 333 bytes, 51 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `mg_entry` | `0x63d8b20..0x63d8b8c` | 108 | 17 | Entry, arg setup, scalar adds `+0xc00..+0xc38` |
| `mg_scalar` | `0x63d8b8c..0x63d8be0` | 84 | 12 | Loop-end lea, scalar adds `+0xc30..+0xc58`, nopl |
| `mg_loop` | `0x63d8be0..0x63d8c63` | 131 | 19 | Loop head, pre-advance loads, `+0x180` advance, first pair adds/stores |
| `mg_exit` | `0x63d8e5d..0x63d8e67` | 10 | 3 | Loop exit test, jne loop head, ret |

- The rest of the loop body (the remaining 22 pair adds per chunk,
  repeated identically for 8 iterations) is verified by the static
  verifier's whole-loop checks, not exhibited: 24 store offsets per
  chunk, each stored exactly once; every store offset has a matching
  src load (22 negative-displacement loads plus the 2 pre-advance
  loads) and dst load; 24 `paddq` instructions; all jump targets
  inside the FDE.
- Census: direct `E8` call sites to `0x63d8b20`: 2 — `0x63b9190`
  (inside FDE `0x63b9180..0x63b91d2`, cited only) and `0x63b9272`
  (inside FDE `0x63b91e0..0x63b930c`, cited only). Direct `E9`
  jump sites: 0. Rip-relative `LEA` sites: 0. `.rela.dyn`
  addends equal to `0x63d8b20`: 0 of 60,723 entries. Internal
  calls within the FDE: 0. Internal jump targets: the loop-back
  `jne 0x63d8be0` only. One `ret` site: `0x63d8e66`.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#248 (1206 unique exhibit/FDE ranges checked across the
  merged tree and the prior worktree records, deduplicated by real
  path, 0 overlaps) and no other contributor's topic, addresses, or
  tables. The reset, the insert, the register, the re-register, the
  size mapper, the handoff, the post-remove unlink, the give-back,
  the removal entry, the class remove, the entry probe, the gate,
  the driver, and the allocator thunk are cited by address, not
  claimed here.

## Corrections to earlier packets

- **#248 confirmed and related.** The reset's neighbour is this
  merge: the reset zeroes a context, this function adds one context
  into another, and the merged span is a prefix of the reset span
  (`+0x0..+0xc60` of `+0x0..+0x14a0`). The reset's slot table,
  bitmap, and anchor are outside the merged span.
- **#247 confirmed.** The insert's slot table, bitmap, and anchor
  are untouched here; this function moves counter state only.
- **#246 confirmed.** Its global triple and `+0x420`-based counter
  region are exactly the kind of state this merge accumulates, but
  no counter value is set here — only added.
- **#244 confirmed.** Its slot-pointer table and bitmap are outside
  the merged span; the merge does not move list state.
- **#243 confirmed.** The give-back's decrements and this merge's
  increments operate on the same counter region, in opposite
  directions, but on different objects (give-back on one context,
  merge across two).
- **#242, #241, #240, #239, #238, #236, #235, #234, #233, #232,
  #216 confirmed.** Nothing of theirs is re-claimed here.

## Unresolved

- Which object pair the two callers merge in the live call graph:
  caller A passes its arguments straight through, caller B passes a
  third argument as dst and `object + 0x560` as src, but neither
  caller FDE is decoded end to end here, so the domain roles
  (per-shard vs global accumulator, or other) are not claimed.
- Why the last 32 bytes (`+0xc60..+0xc80`) are added inline by both
  callers instead of inside the merge — whether the merge's span is
  a deliberate 396-qword boundary or the callers share a second
  tail structure is not decided here.
- Whether caller B's tail source (`object + 0x1628`/`+0x1638`)
  belongs to the same logical structure as its merge source
  (`object + 0x560`), or to a different sub-object.
- The domain meaning of the `+0x0..+0x400` helper region beyond its
  64 16-byte slots (same reservation as #248), and of the counter
  region past `+0xc60` (same stride-bound reservation as #248).
- What the next FDE `0x63d8e70..0x63d906b` does — this is #250's
  question.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Verification

- `tools/node115_lu_context_merge.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, one `ret` site, loop-back jump target,
  loop chunk coverage (24 stores, src/dst loads, 24 paddq), scalar
  tail qword offsets, census, neighbour disjointness, MANIFEST
  coverage (13 entries).
- `tests/test_node115_lu_context_merge.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7167 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout (verified for #242; base unchanged
  since), so this is pre-existing upstream staleness from
  the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone. Note: the worktree's `AGENTS.md`
  says to run `make verify test catalogue-check`, but the
  parent task's explicit no-full-`make test` rule outranks
  it; the deviation is disclosed here, as in #245/#246/#247/#248.
