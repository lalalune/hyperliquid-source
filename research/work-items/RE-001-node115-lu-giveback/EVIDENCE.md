# RE-001-node115-lu-giveback: the give-back driver before removal

- Component ID: RE-001-node115-lu-giveback
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (confirmed before analysis)
- Claim status: observation for all exhibited bytes and the accounting
  identity; inference for the count/byte-total/remainder names of the
  slot and global triples; unresolved for the tail target's body, the
  caller FDEs' flag states, the `+0x200` writers, and the `+0x23` reader
- Scope included: FDE `0x63d8e70..0x63d906b` (507 bytes) end to end,
  its 2 internal calls, its 8 direct call sites, its tail jump.
  Scope excluded: the tail target FDE `0x63d84e0..0x63d8622`, the
  three caller FDEs, the size mapper `0x63e8bf0`, the removal entry
  `0x63d8630` — all cited by address only.

## Reproduce

Working directory: the worktree at upstream main `05bc2de30`.
Tool versions: system `objdump`, `readelf`, `python3` (no version pin
claimed; the verifier re-derives everything from the binary).
Commands: `objdump -d --start-address=0x63d8e70
--stop-address=0x63d906b artifacts/node/115/hl-node`;
`readelf --debug-dump=frames` for the FDE bounds;
`python3 tools/node115_lu_giveback.py` (exit 0);
`python3 -m unittest tests.test_node115_lu_giveback` (10/10).
No execution of the node binary, no network, no side effects beyond
reading the binary.

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (verified against
the PT_LOAD segment `off=0x1418300 ↔ vaddr=0x1419300`);
`.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is (section
header: address `0x430400`, offset `0x430400`). FDE bounds from
`.eh_frame` (`pc=0x63d8e70..0x63d906b`), not from an endbr64 scan.
Entry bytes `f3 0f 1e fa` (`endbr64`); single `ret` at `0x63d8f98`;
calls at `0x63d8ea5` → `0x63e8bf0` and `0x63d9000` → `0x63d8630`
(both rel32-verified); tail jump at `0x63d9017` → `0x63d84e0`.
Raw disassembly of the six exhibits sits beside this record as
`.hex` + `.objdump.txt` pairs; the 0x200 arm and the overflow stub
are covered by the verifier's key-byte checks (`.rodata` constant
`(−1, −512)` at file offset `0x451800`, slot bases `0x1020`/`0x1050`,
stub `r10d = 0x2970 = 48*199 + 0x420`). Analysis is complete over the
FDE: every direct jump target lies inside the FDE except the stated
tail jump; the `nopl` gaps are padding, not claimed.

Callers/callees: 8 direct `E8` call sites to this FDE, all
objdump-confirmed (5 in FDE `0x63b7900..0x63b7ee6`, 2 in FDE
`0x63b7ef0..0x63b8157`, 1 in FDE `0x63b8820..0x63b8d85`); 0 `E9`
sites; 0 rip-relative `LEA` sites; 0 `.rela.dyn` addends of 60,723.
ABI/layout observations: first argument kept in `rbp` across all
paths; block in `rbx`; the slot address adds `((-byte[block+0x10]) &
0x18)` to the base; the size index uses the #242 scheme with a
48-byte stride and a `+0x420` base, clamped to a minimum of 14, shift
`clamped − 3` except `12` when `clamped == 14`; overflow maps to
index 199. No `.bss` value is read or claimed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet; the packet is evidence only, with a static verifier and
unit tests that re-derive the exhibited bytes from the target binary.

## Results and limitations

Machine-readable metrics: 6 exhibits, 387 bytes, 93 strict
instructions; verifier exit 0; unit tests 10/10; `make verify` exit 0;
`make catalogue-check` exit 2 with `Stale catalogue: README.md`,
pre-existing on a pristine `05bc2de30` checkout (not a packet
regression); full `make test` not attempted (584 files on the new
base; hours-long, VM-restart liable per #234). What remains unknown:
the tail target's body, the caller FDEs' pre/post behaviour and flag
states, the `+0x200` writers, the `+0x23` reader, the slot/global
triples' domain names, and whether the `+0x1020`/`+0x1050` bases
share a table with the `+0x420` size table. Next question (#244):
decode the tail-jump target FDE `0x63d84e0..0x63d8622` end to end,
and, if it is small, what the three caller FDEs establish before
calling this function.
