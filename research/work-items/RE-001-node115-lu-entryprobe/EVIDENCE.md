# RE-001-node115-lu-entryprobe: the size-class entry probe

- Component ID: RE-001-node115-lu-entryprobe
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes, `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed by fetch before analysis; unmoved during the work)
- Claim status: observation for the FDE bytes, the census, and the
  caller-site tests; inference for the bitmap-bit nonemptiness
  reading; unresolved for `0x63b9d10`, the neighbour caller FDE,
  and the bitmap bit's domain meaning
- Scope included and excluded: included is the single FDE
  `0x63b9680..0x63b968c` and the two call sites that test its
  result (cited, not claimed). Excluded are the handoff, the
  register, the gate, the driver, the class insert, the allocator
  thunk, the neighbour caller FDE, and `0x63b9d10` — all cited by
  address only.

## Reproduce

Worktree `~/workspace/hl-wt-calls240-115`, branch
`codex/re-004-calls240-115`, at upstream main `05bc2de30`.
Static analysis only; the binary was never executed.

- `sha256sum artifacts/node/115/hl-node`
  → `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- `readelf --debug-dump=frames-interp artifacts/node/115/hl-node`
  → `FDE cie=00000000 pc=00000000063b9680..00000000063b968c`
- `objdump -d --start-address=0x63b9680 --stop-address=0x63b968c
  artifacts/node/115/hl-node`
  → `endbr64; cmpq $0x0,(%rdi); sete %al; ret`
- `python3 tools/node115_lu_entryprobe.py` → exit 0
- `python3 -m unittest tests.test_node115_lu_entryprobe` → 10/10
- `make verify` → exit 0 (tally in README, verified in this worktree)
- `make catalogue-check` → fails with `Stale catalogue: README.md`,
  identically on a pristine `05bc2de30` checkout (pre-existing
  upstream staleness, not a packet regression)
- Full `make test` → not attempted on the new base (584 files;
  hours-long, VM-restart risk shown in #234)

Coordinate system: `.text` file offset = VA − 0x1000 (re-derived
from program headers: PT_LOAD file offset `0x1418300` ↔ vaddr
`0x1419300`); `.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA
as-is. RELATIVE `.got` slots are zero-filled in the file, so the
GOT census uses `.rela.dyn` addends (60,723 entries).

## Evidence

Original addresses (VA) and file offsets (VA − 0x1000 for `.text`):

- FDE `0x63b9680..0x63b968c`, 12 bytes:
  `f3 0f 1e fa` (endbr64), `48 83 3f 00` (cmpq $0,(%rdi)),
  `0f 94 c0` (sete %al), `c3` (ret at `0x63b968b`).
- Padding: `int3` × 12 at `0x63b9674..0x63b9680` (after FDE
  `0x63b9660..0x63b9674`), `int3` × 4 at `0x63b968c..0x63b9690`
  (before the #231 consumer FDE at `0x63b9690`).
- Census over the whole `.text` section (file offset `0x1418300`,
  size `0x4fd7700`): direct `E8` → `0x63b9680` at `0x63d8717`
  (`e8 64 0f fe ff`) and `0x63d8874` (`e8 07 0e fe ff`); 0 `E9`;
  0 rip-relative `LEA`; 0 `.rela.dyn` addend hits out of 60,723.
- Caller-site tests (cited only): `test %al,%al` (`84 c0`) at
  `0x63d871c` (neighbour caller, then bitmap clear on nonzero)
  and at `0x63d8879` (handoff, then bitmap set on nonzero).
- Bitmap writes (cited only): handoff `or` at `0x63d888d`
  (`4e 09 94 ed 00 04 00 00`); neighbour `and` with rotated `~1`
  mask at `0x63d8735` (`4e 21 94 ed 00 04 00 00`).
- Disjointness: the claimed range overlaps no exhibit range in
  the merged tree's `records.json` files (96 exhibit ranges
  checked) nor in the #235–#239 worktree records. The three
  whole-`.text` section extents found in a raw recursive scan
  (`0x1419300..0x63f0a00`) are section metadata, not exhibit
  claims, and are excluded from the exhibit-range check.

Analysis was complete for this FDE: every byte is exhibited, every
branch (none) and call (none) is accounted for, and both call
sites were confirmed by rel32.

## Implementation and comparison

Not yet implemented/measured: no independent Rust reconstruction
of this probe is included in this packet; the verifier is a static
byte checker, not a reimplementation. No Cargo graph, no build
comparison, no equivalence claim is made.

## Results and limitations

- Proven by bytes: the probe returns `%al = 1` iff `[entry] == 0`;
  it reads only the head pointer; both callers test `%al` only;
  the handoff sets the class bitmap bit on a nonzero (empty)
  result and the neighbour caller clears it on a nonzero result.
- Inference only: the bitmap bit tracks class nonemptiness
  (set on first insert, cleared when a class becomes empty).
- Unknown: what `0x63b9d10` does; what the neighbour caller FDE
  `0x63d8630..0x63d8790` is; the bitmap bit's domain meaning;
  whether any caller tests more than `%al`.
- Gate coverage: this packet's verifier, unit tests, and
  `make verify` cover the packet's own files and the manifest
  catalogue; they do not cover the full 584-file test suite,
  which was not run (see Reproduce).

Next question (#241): decode `0x63b9d10` end to end — what it
does with the (entry, block) pair from the neighbour caller, and
whether it removes, unlinks, or otherwise empties a size-class
entry.
