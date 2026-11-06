# RE-001-node115-lu-postremove: bounded question

- Component ID: node #115 lu post-remove (tail-jump target of the #243 give-back)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation (bytes, stores, rel32 targets, census);
  inference (circular doubly-linked list reading, slot-table unification);
  unresolved (bitmap set side and readers, slot-table identity, insert side,
  caller-FDE establishment, field domain meanings)
- Scope included and excluded: included — FDE `0x63d84e0..0x63d8622`
  end to end, its slot-number formulas, unlink stores, head case, bitmap
  clear, census. Excluded — the give-back caller (cited only), the size
  mapper body (cited only), the three give-back caller FDEs (cited only),
  the bitmap set side and readers, any insert side for the per-slot list.

## Reproduce

Worktree `~/workspace/hl-wt-calls244-115`, branch
`codex/re-004-calls244-115`, base `05bc2de30`. No execution of the
node binary at any point; all reads are static byte reads and objdump
disassembly:

- `objdump -d --start-address=0x63d84e0 --stop-address=0x63d8622
  artifacts/node/115/hl-node`
- `python3 tools/node115_lu_postremove.py` (static verifier, exit 0)
- `python3 -m unittest tests.test_node115_lu_postremove` (10/10)
- `make verify` (exit 0; see README for the tally)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md` on the new base, identical on a pristine `05bc2de30`
  checkout as verified for #242; base unchanged since)

No execution side effects; no network, no signing, no chain actions.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000, re-derived
from program headers (PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`,
delta `0x1000`); `.rodata` = VA as-is; `.data.rel.ro`/`.got` =
VA − 0x2000. RELATIVE `.got` slots are zero-filled in the file, so
the GOT census uses `.rela.dyn` addends (60,723 entries).

FDE bounds confirmed by `.eh_frame` (`pc=0x63d84e0..0x63d8622`,
322 bytes). Entry bytes `55 48 89 fd 53 48 89 f3` (`push %rbp`,
no `endbr64`). `int3` padding `0x63d84d1..0x63d84e0` (15 bytes)
and `0x63d8622..0x63d8630` (14 bytes). Two `ret` sites
(`0x63d8551`, `0x63d8609`). One internal call (`0x63d8566` →
`0x63e8bf0`, rel32-verified). No tail jump out; all direct jump
targets inside the FDE. Full disassembly is preserved in the six
`.objdump.txt` exhibits beside this record; raw bytes in the six
`.hex` exhibits.

Census (raw `.text` scan, objdump-confirmed): `E8` to `0x63d84e0`:
none; `E9`: exactly `0x63d9017` (the #243 give-back tail jump);
rip-relative `LEA` (`48`/`4c`/`49`/`4d 8d` forms): none;
`.rela.dyn` addends equal to `0x63d84e0`: 0 of 60,723. A scan for
external branches landing anywhere inside the FDE returns only
`0x63d9017` → `0x63d84e0`, so the tail jump is the sole entry
from outside.

Disjointness: 1400 exhibit ranges from the merged tree and the
prior worktree records, 0 overlaps with this FDE or its exhibits.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet; the packet is evidence only. The verifier is a static
byte checker, not a reimplementation. No Cargo graph, no build
equivalence claim.

## Results and limitations

Machine-readable metrics with explicit denominators: 6 exhibits,
281 bytes, 73 strict instructions; FDE 578 bytes; census 1 `E9`
site, 0 `E8`, 0 `LEA`, 0/60,723 `.rela.dyn` hits; MANIFEST 17
entries, all hashes matching; verifier exit 0; unit tests 10/10.

What passed: all static gates above. What failed: `make
catalogue-check` exit 2 with pre-existing upstream staleness (not
a packet regression). What remains unknown: the bitmap set side
and readers; slot-table identity across the two arms; the list
insert side; the three give-back caller FDEs' establishment; the
domain meanings of `[block+0x10]` and `[block+0xb0]` beyond their
roles here.

Next question (#245): decode the three give-back caller FDEs
(`0x63b7900..0x63b7ee6`, `0x63b7ef0..0x63b8157`,
`0x63b8820..0x63b8d85`) — what they establish before calling the
give-back function, and which `+0x12`/`+0x13` flag states they set
— deciding who drives give-back and under what conditions.
