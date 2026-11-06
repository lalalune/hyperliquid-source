# RE-001: the node #115 lu wait provenance — mov-shape callers pass the same record type

Packet #252's next question: trace the provenance of the register-passed
and memory-loaded arguments to the lu wait helper — starting with the
largest caller FDE (`0x63a5bf0..0x63a6470`, 18 helper sites) — deciding
whether the `mov`-shape callers pass the same record type through, or a
different one.

Answer: the same record type, through every provenance shape in this
FDE. All 18 helper sites were traced to their record pointers: 8 records
embedded at fixed offsets inside a per-object structure, 1 record
computed in a loop (object + group offset + `i * 0xe0`), 1 record reached
through a memory-loaded pointer field, and 8 global `.bss` records. At
every site the mutex is at record `+0x40`, the flag at record `+0x68`,
and — new in this packet — a caller-side triple at record `+0x28`
(distinct-tag count), `+0x30` (last tag), `+0x38` (acquisition count).
The record pointer's origin varies; the layout does not.

## The FDE

`0x63a5bf0..0x63a6470` (2176 bytes, `endbr64` entry, single `ret` at
`0x63a615b`) is a walk over many waiter records. Its first argument is
saved in `r13` at entry and used as the tag at every site; after each
successful trylock it calls the work function `0x63bf7f0` (cited only)
with `(rdi = tag, rsi = record)`. On trylock failure each site follows
#252's shared pattern: call the wait helper `0x63bf680` on the record,
set the record's flag byte to 1, and jump back to the counting step.

The walk has four parts:

1. **Object table.** A table of object pointers at `.bss` `0x65096c0`
   (count from the call at `0x634eba0`, cited only; 8 bytes per entry).
   Each non-null object is processed in turn; the current object is kept
   in `0x10(%rsp)`.
2. **Per-object embedded records.** For each object, the function walks
   8 records embedded at fixed offsets (see the site table below),
   plus the loop array described next, plus one pointer-chained record.
3. **Loop array.** An outer loop over 36 groups (bounds-derived:
   descriptors at `0x6711b40+0x14`, stride `0x28`, end `0x6711b40+0x5b4`)
   with a per-group dword offset read from the `.bss` array at
   `0x6511780` (advanced by 4 per group). The inner loop walks records
   at `object + group_dword + i * 0xe0` (stride `0xe0`, `rbp = i*0xe0`).
4. **Global records.** After the object loop, 7 more global `.bss` records
   are processed in the same pattern, plus the first global record
   `0x6712160` at the head of the function (8 global sites in total).

The `.bss` contents (table entries, group dwords, group descriptors) are
runtime-filled and not readable from the file; the walk structure itself
is proved by the code, the table contents are not claimed.

## The record layout, extended

Packet #251 proved the helper-side fields (`+0x00..+0x24` stats,
`+0x40` mutex, `+0x68` flag). This packet adds the caller-side triple,
proved at all 18 sites: on every successful-trylock path the caller
does `acq(+0x38) += 1`, compares the tag against `last(+0x30)`, and on
mismatch does `distinct(+0x28) += 1` and `last(+0x30) := tag`. Packet
#250's caller B fits the same triple: its lock-1 counters
(`+0xe8`/`+0xd8`/`+0xe0` on an object whose record is at `+0xb0`) are
record `+0x38`/`+0x28`/`+0x30`, and its lock-2 counters (`+0x78`/`+0x68`/
`+0x70` on a record at `+0x40`) are the same three slots.

| Offset | Meaning |
|---|---|
| `+0x00` | Total waited nanoseconds, slow path only (#251) |
| `+0x08` | Max single wait, nanoseconds (#251) |
| `+0x10` | Blocking-path (slow) acquisition count (#251) |
| `+0x18` | Successful acquisition count (#251) |
| `+0x20` | High-water ticket (#251) |
| `+0x24` | Live waiter count (#251) |
| `+0x28` | Caller-side distinct-tag count (this packet) |
| `+0x30` | Caller-side last tag (this packet) |
| `+0x38` | Caller-side acquisition count (this packet) |
| `+0x40` | The pthread mutex (40 bytes, `+0x40..+0x68`) (#251) |
| `+0x68` | Contended flag byte (#251) |

## All 18 sites

| Site | Record | Mutex | Flag | Triple | Provenance |
|---|---|---|---|---|---|
| `0x63a610a` | `r15` (computed) | record `+0x40` | record `+0x68` | `r15+0x28/+0x30/+0x38` | loop: object + group dword + `i*0xe0` |
| `0x63a615f` | object `+0x28a8` | object `+0x28e8` | object `+0x2910` | object `+0x28d0/+0x28d8/+0x28e0` | embedded fixed offset |
| `0x63a6178` | object `+0x115c0` | object `+0x11600` | object `+0x11628` | object `+0x115e8/+0x115f0/+0x115f8` | embedded fixed offset |
| `0x63a6191` | `ptr+0x20` | `ptr+0x60` | `ptr+0x88` | `ptr+0x48/+0x50/+0x58` | memory-loaded: `ptr = [object+0x13458]` |
| `0x63a61a6` | object `+0x133b0` | object `+0x133f0` | object `+0x13418` | object `+0x133d8/+0x133e0/+0x133e8` | embedded fixed offset |
| `0x63a61c0` | object `+0x2928` | object `+0x2968` | object `+0x2990` | object `+0x2950/+0x2958/+0x2960` | embedded fixed offset |
| `0x63a61da` | object `+0x10ec8` | object `+0x10f08` | object `+0x10f30` | object `+0x10ef0/+0x10ef8/+0x10f00` | embedded fixed offset |
| `0x63a61f4` | object `+0xc1c8` | object `+0xc208` | object `+0xc230` | object `+0xc1f0/+0xc1f8/+0xc200` | embedded fixed offset |
| `0x63a620d` | object `+0x75d8` | object `+0x7618` | object `+0x7640` | object `+0x7600/+0x7608/+0x7610` | embedded fixed offset |
| `0x63a6227` | object `+0x29e8` | object `+0x2a28` | object `+0x2a50` | object `+0x2a10/+0x2a18/+0x2a20` | embedded fixed offset |
| `0x63a6240` | `0x6712160` | `0x67121a0` | `0x67121c8` | `0x6712188/+0x6712190/+0x6712198` | global `.bss` record |
| `0x63a63f8` | `0x6711ac0` | `0x6711b00` | `0x6711b28` | `0x6711ae8/+0x6711af0/+0x6711af8` | global `.bss` record |
| `0x63a640b` | `0x6714620` | `0x6714660` | `0x6714688` | `0x6714648/+0x6714650/+0x6714658` | global `.bss` record |
| `0x63a641d` | `0x6717620` | `0x6717660` | `0x6717688` | `0x6717648/+0x6717650/+0x6717658` | global `.bss` record |
| `0x63a642c` | `0x6715800` | `0x6715840` | `0x6715868` | `0x6715828/+0x6715830/+0x6715838` | global `.bss` record |
| `0x63a643f` | `0x67158a0` | `0x67158e0` | `0x6715908` | `0x67158c8/+0x67158d0/+0x67158d8` | global `.bss` record |
| `0x63a6450` | `0x6714520` | `0x6714560` | `0x6714588` | `0x6714548/+0x6714550/+0x6714558` | global `.bss` record |
| `0x63a6461` | `0x67145a0` | `0x67145e0` | `0x6714608` | `0x67145c8/+0x67145d0/+0x67145d8` | global `.bss` record |

Note on #252's shape classification: in this FDE, all 18 sites set
`rdi` by `mov reg` — the global records are `lea`'d into a register far
before the call, so the nearest writer is the `mov`. Under #252's
linear-predecessor classification these all count as `mov reg` shape.
This packet traces past that nearest writer to the actual record
source, which is what answers the provenance question: the `mov` shape
hides four different sources, all yielding the same record type.

## Exhibits

6 exhibits, 113 bytes, 26 strict instructions (strict = mnemonic-line
count: address + bytes field + tab + mnemonic; objdump
byte-continuation lines excluded). All lie inside the FDE
`0x63a5bf0..0x63a6470`.

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `pv_loop_calc` | `0x63a60e3..0x63a60fb` | 24 | 6 | Loop record computation: group dword + object + `i*0xe0`, mutex lea at `+0x40` |
| `pv_triple` | `0x63a60a8..0x63a60bc` | 20 | 5 | Caller triple on the loop record: `+0x38` acq, `+0x30` last-tag compare, `+0x28` distinct |
| `pv_loop_wait` | `0x63a6107..0x63a6116` | 15 | 4 | Loop-record wait: computed record in `rdi`, helper call, flag set at `+0x68`, jump back |
| `pv_ptr_load` | `0x63a6008..0x63a6017` | 15 | 3 | Memory-loaded pointer: `ptr = [object+0x13458]`, mutex `ptr+0x60`, record `ptr+0x20` |
| `pv_ptr_wait` | `0x63a618e..0x63a61a3` | 21 | 4 | Pointer-record wait: record in `rdi`, helper call, flag set at `ptr+0x88` = record `+0x68` |
| `pv_glob_wait` | `0x63a645e..0x63a6470` | 18 | 4 | Global-record wait: `0x67145a0` in `rdi`, helper call, flag set at `+0x68`; ends at the FDE end |

The other 12 sites' waits, trylocks, flag sets, and triple updates are
surveyed observations recorded in `records.json` and checked by the
verifier's byte reads and rel32 checks, not claimed exhibits.

## Disjointness

The exhibits overlap no claimed range from packets #183–#252 (checked
across the merged tree and the prior worktree records, deduplicated by
real path with ranges deduplicated as a set, own slug excluded, 0
overlaps) and no other contributor's topic, addresses, or tables.
Census and cited-only metadata ranges are excluded from the claimed
set: packet #252's census records this very FDE as its
`largest_caller_fde` while stating no byte of it is claimed, so
counting that metadata range as a claim would falsely block the
follow-up #252 itself invited. Packet #252 counted this FDE's 18 sites
in its census but claimed no byte of it; these exhibits are the first
claims inside it. The helper
FDE, the work function, the merge callers, the merge, the give-back,
the reset, the insert, the register, the re-register, the size mapper,
the handoff, the post-remove unlink, the removal entry, the class
remove, the entry probe, the gate, the driver, and the allocator thunk
are cited by address, not claimed here.

## Corrections to earlier packets

- **#252 confirmed and extended.** Its open question — the provenance
  of the `mov`-shape arguments — is answered for the largest caller
  FDE: the `mov` shape hides four sources (embedded offset,
  loop-computed, memory-loaded pointer, global), all yielding the same
  record type. #252's flag-clear observation is confirmed again here:
  every site's unlock path clears its record's `+0x68` flag before
  unlocking.
- **#251 confirmed and extended.** Its record table gains the
  caller-side triple at `+0x28`/`+0x30`/`+0x38`, proved at all 18
  sites here and consistent with #250's caller-B counters.
- **#250 confirmed.** Caller B's two records are two instances of
  this layout; its counter triples are the same three slots.
- **#249, #248, #247, #246, #243, #232 confirmed.** Nothing of theirs
  is re-claimed here.

## Unresolved

- The contents of the `.bss` object table, group dword array, and
  group descriptors — runtime-filled, not file-readable.
- What the work function `0x63bf7f0` does with `(tag, record)` after
  each successful trylock — cited only.
- The provenance of the `mov`-shape arguments in the other 384 caller
  FDEs — only this FDE's 18 sites are traced.
- The domain identity of the objects and locks in this FDE — no
  function names are claimed.
- Whether any caller reads the statistic fields (`+0x00..+0x24`)
  after the wait returns — no such read was found in this FDE.
- `.bss` contents are runtime-filled and not readable from the file;
  nothing here depends on them.

## Next question (#254)

Decode the work function `0x63bf7f0` end to end: what it does with
`(tag, record)` after each successful trylock — deciding what this
largest caller FDE actually accomplishes once it holds each lock.

## Verification

- `tools/node115_lu_wait_provenance.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds/entry/padding, one `ret` site, all 18 helper-site
  rel32s, exhibit call/trylock rel32s, surveyed cross-check bytes,
  record-offset arithmetic for all 18 sites, neighbour
  disjointness, MANIFEST coverage (17 entries).
- `tests/test_node115_lu_wait_provenance.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
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
  it; the deviation is disclosed here, as in #245–#252.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63a5bf0..0x63a6470`, 2176 bytes); `endbr64` entry;
  `int3` padding `0x63a5bef..0x63a5bf0` (1 byte, after the
  preceding FDE ending at `0x63a5bef`) and no padding after
  (the next FDE starts exactly at `0x63a6470`, cited only).
  Static analysis only; the binary was never executed.
