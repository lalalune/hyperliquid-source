# RE-001-node115-lu-dblinsert: the node #115 lu double slot-insert caller

- Component ID: RE-001-node115-lu-dblinsert
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), artifact `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte-level claims; inference is
  marked as such in README; unresolved items are listed, not inferred
- Scope included and excluded: included — the single FDE
  `0x6363660..0x63637e2` (386 bytes) and its census; excluded — the
  slot-insert FDE `0x63ac0d0..0x63ac472` (#219), the caller FDEs
  starting `0x63e9cd0` / `0x63ead50`, the allocator pool slots
  (#216/#217/#218), all cited by address only

## Reproduce

Working directory: a worktree of upstream main `8fd8db6` at
`~/workspace/hl-wt-calls220-115` (local branch
`codex/re-004-calls220-115`; main clone HEAD untouched at `2993e46`).
Tool versions: GNU objdump 2.42, readelf (binutils 2.42), python3
stdlib only. Commands:

- `objdump -d --start-address=0x6363660 --stop-address=0x63637e2
  artifacts/node/115/hl-node` (full FDE, 108 lines including headers)
- Per-exhibit objdump with the exhibit ranges in `records.json`
- `python3 tools/node115_lu_dblinsert.py` (static verifier, exit 0)
- `python3 -m unittest tests.test_node115_lu_dblinsert` (9/9)
- `make doctor` (analysis_ready true), `make verify`,
  `make catalogue-check`, `make test` (see Results)

No execution of the node binary at any point; no side effects beyond
the packet files listed in the MANIFEST.

## Evidence

Coordinate system: VA addresses as shown by objdump; `.text` file
offset = VA − 0x1000 (`.text` VA `0x1419300`, file offset
`0x1418300`); `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA
as-is. RELATIVE `.got` slots are zero-filled in the file, so the GOT
census uses `.rela.dyn` addends (60,723 entries; section
`[9] .rela.dyn`, file offset `0x6be8`, size `0x163cc8`).

Validated boundaries: FDE `0x6363660..0x63637e2` (386 bytes). Entry
`endbr64` at `0x6363660`; last instruction is the `jmp` at
`0x63637dd` ending at `0x63637e2`; padding (`int3`) follows, then the
next function prologue at `0x63637f0`. Two `ret` sites: `0x6363720`
(insert path) and `0x636379d` (evict path). Exactly 2 `call`
instructions, both `call 0x63ac0d0` (`0x636370d`, `0x63637c7`).
Internal E9 jumps only: `0x63637b4 -> 0x63636c2`,
`0x63637dd -> 0x6363692`, plus the short `jmp` at `0x63637d4`.

Raw disassembly: full FDE in scratch (`fde_full.txt`, small); the 5
exhibits in this packet (226 bytes, 61 strict mnemonics):

- `di_entry` `0x6363660..0x6363685` (37B, 11 strict): entry, global
  lea, obj field load, global load, unsigned gate compare
- `di_cmp` `0x63636c2..0x6363703` (65B, 21 strict): head load, NULL
  test, `setb`/`sbb` signum on `+0x20` then `+0x8`, `cmp $0x1` branch
- `di_insert` `0x6363703..0x6363721` (30B, 8 strict): slot lea, node
  mov, call 1, `+0xb8` counter, epilogue, ret (one objdump
  byte-continuation line excluded from the strict count)
- `di_evict` `0x6363740..0x6363788` (72B, 17 strict): self-pair
  `movups`, anchor load, NULL test, anchor-splice writes
- `di_call2` `0x63637c0..0x63637d6` (22B, 4 strict): slot lea, call 2,
  `+0xb8` counter, shared-tail jump (one byte-continuation line
  excluded from the strict count)

Callers/callees: callee is only the slot-insert helper `0x63ac0d0`
(#219). Callers of this FDE (whole-`.text` E8 rel32 scan + per-site
objdump confirmation): `0x63ea135`, `0x63ea495`, `0x63eaad3` (FDE
starting `0x63e9cd0` — the only `endbr64` prologue in
`0x63e9cd0..0x63ead50`), `0x63eb134`, `0x63eb20a`, `0x63eb356` (FDE
starting `0x63ead50` — the only `endbr64` prologue in
`0x63ead50..0x63eb400`, next prologue `0x63eb870`). Caller FDE ends
are next-prologue bounds; their purposes are not decoded here. E9/LEA
census 0; GOT addend hits 0.

Source mapping evidence: none claimed — this is a binary-only packet;
no source lines are asserted.

ABI/layout observations: args (rdi unused, rsi obj, rdx node, rcx
ctx); ctx fields `+0xc0` head, `+0xc8` slot (16B: head + second
word), `+0xd8` anchor, `+0xa8` head-change counter, `+0xb8`
slot-insert counter; node fields `+0x0` tag word, `+0x8`/`+0x20`
sort key, `+0x28`/`+0x30` link words; obj field `+0x13450` (u32);
`.bss` threshold `0x650969c` (NOBITS — value not present in the
file, so no value is claimed for it). The second argument's
`+0x13450` offset and the `.bss` address are read directly from the
disassembly, not from any source.

Analysis was complete over the FDE (all 386 bytes disassembled and
read); caller FDEs were not decoded beyond their call sites.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is proposed in
this packet, and no source comparison is claimed. The packet is
observation-only evidence for a future implementation task.

## Results and limitations

Metrics with denominators: verifier exit 0 (5 excerpts, 226 bytes, 61
strict, 13 key-byte sites, 2 calls, census 6 E8, MANIFEST 15/15);
unit tests 9/9; `make verify` exit 0; `make catalogue-check` exit 0;
`make test` — wrapper exit 2, 77 files attempted, 1 failed (the
pre-existing test_node115_catalogue Errno 18 cross-device-link error,
identical on pristine checkouts, not a packet regression); this
packet's file [36/77] passes 9/9.

What remains unknown, and why: the `+0x28`/`+0x30` structure invariant
(list versus tree, and what the block-1 rotation preserves) cannot be
decided from one FDE — its pointer writes are recorded exactly and
the invariant is left open; the ctx object's semantic identity and
the head/anchor distinction need a caller FDE decode; the obj
`+0x13450` field, the `.bss` threshold, and the head tag bits
(`>> 28) & 0x3ff`) need the producers of those values, which are
outside this FDE. No gate is requested by this packet.

Next question: decode the FDE starting at `0x63e9cd0` end to end:
what ctx object it passes to `0x6363660`, what drives its three call
sites (`0x63ea135`, `0x63ea495`, `0x63eaad3`), and how its nodes
reach the head/slot/anchor state machine.
