# RE-001-node115-lu-consume: the consume helper — block stamp, fixed header, zeroed tail

- Component ID: RE-001-node115-lu-consume
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed before analysis; binary byte-identical to the `8fd8db6` base)
- Claim status: observation for all byte claims; inference flagged as such
  (the "registration, not slice" reading); unresolved items listed at the end
- Scope included and excluded: FDE `0x63ba600..0x63ba672` only, plus the
  `.rodata` constant at `0x453a60` it loads. The gate FDE, the driver FDE,
  the allocator thunk, and the resolver/release helpers are cited by
  address only. No other contributor's topic, addresses, or tables are used.

## Reproduce

Working directory: a worktree of upstream main `05bc2de30` with
submodules initialized (`git submodule update --init --recursive --force`
plus `git lfs pull`). No execution of the node binary at any point;
all evidence is static byte reads and `objdump -d` disassembly.

- `objdump -d --start-address=0x63ba600 --stop-address=0x63ba672
  artifacts/node/115/hl-node` reproduces the full FDE disassembly.
- `python3 tools/node115_lu_consume.py` runs the static verifier
  (exit 0): SHA/size, exhibit bytes, strict counts, FDE bounds,
  single `ret`, zero calls, zero branches, key stores and call
  rel32s, rodata constant, full census, neighbour disjointness,
  MANIFEST coverage (11 entries).
- `python3 -m unittest tests.test_node115_lu_consume` runs the unit
  tests (10/10): regeneration comparison, tamper control, FDE
  bounds, key bytes, strict counts, records match, no-branch
  check, untouched-gap check.
- `make verify` exits 0. `make catalogue-check` fails on the new
  base with `Stale catalogue: README.md`, identically on a pristine
  `05bc2de30` checkout — pre-existing upstream staleness from the
  merge wave, not a packet regression (packet files are untracked
  and the check reads tracked files only).
- Full `make test` was not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be liable
  to VM-restart termination). This packet's own file passes 10/10
  standalone.

## Evidence

Original addresses and coordinate system: virtual addresses (VA) as
shown by `objdump`; `.text` file offset = VA − 0x1000;
`.rodata` file offset = VA. FDE bounds confirmed by `.eh_frame`
(`pc=0x63ba600..0x63ba672`); following bytes `0x63ba672..0x63ba680`
are `int3` padding; next function starts with `endbr64` at
`0x63ba680`. Analysis is complete over the FDE (all 114 bytes,
20 strict instructions); nothing was timed out or range-limited.

Raw disassembly (3 exhibits, 114 bytes, 20 strict):

- `cs_entry` (`0x63ba600..0x63ba61e`, 30 bytes, strict 6):
  entry, `movdqa` constant load from `.rodata 0x453a60`, `pxor`
  zero, cursor store `[block] := rsi`, counter store
  `[block+8] := rdx`, `movl $0x100,0x10(%rdi)`.
- `cs_flags` (`0x63ba61e..0x63ba638`, 26 bytes, strict 4):
  `movb $0,0x14`, `movl $0,0x20`, `movb $0,0x24`,
  `movq $0,0xb0`.
- `cs_zero` (`0x63ba638..0x63ba672`, 58 bytes, strict 10):
  `movups %xmm0,0x60` (the `0x200` constant), eight `movups
  %xmm1` zero stores (`+0x70`..`+0xaf`, `+0xb8`..`+0xf7`),
  single `ret` at `0x63ba671`.

Callers (whole-`.text` byte scan + per-site disassembly;
`.rela.dyn` for GOT, 60,723 entries): direct `E8` sites 2 —
`0x63b86bc` (gate main path) and `0x63b87b9` (gate drain path),
both with the same arg shape (`rdi` = alloc, `rsi` =
`[context+0xe0]`, `rdx` = `[context+0xf8]` old). Direct `E9`
sites 0, rip-relative `LEA` sites 0, `.rela.dyn` addends 0.
Internal calls within the FDE: 0. Internal branches: none.

Gate-side argument setup (cited, verified by disassembly):
main path loads `rdx := [context+0xf8]`, stores `rdx + 1` back,
then calls with `rdx` still holding the old value; drain path
does the same via `rcx`. After the call the gate advances
`[context+0xe0] += 0x200000` / `[context+0xe8] -= 0x200000`
(main) or zeroes both (drain). The cursor is never passed to
the allocator thunk (`0x636b370`, called by the gate with
`(first-arg, [context+0xf0], 0xf8, 0x40)`).

ABI/layout observations: block size `0xf8` equals the gate's
allocator size argument. Written regions: `+0x00..+0x17`,
`+0x20..+0x27`, `+0x60..+0xf7` (with the `+0xb0` hole closed by
its own store). Untouched regions: `+0x18..+0x1f` (8 bytes) and
`+0x28..+0x5f` (56 bytes) — no store to those offsets exists in
the FDE. The `.rodata` constant at `0x453a60` is 16 bytes:
qwords `0x200` and `0`. No rounding or overflow behaviour is
involved; the function is straight-line.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed
for this helper; the packet is evidence only. No Cargo graph,
build, or equivalence claim is made.

## Results and limitations

Metrics: 3 exhibits, 114 bytes, 20 strict instructions, 1 `ret`,
0 calls, 0 branches, census 2 E8 / 0 E9 / 0 LEA / 0 GOT,
MANIFEST 11/11, verifier exit 0, unit tests 10/10, `make verify`
exit 0, `make catalogue-check` fails pre-existing (see above),
full `make test` not attempted (see above).

What remains unknown, stated not inferred: the semantics of the
fixed header words (`+0x10 = 0x100`, `+0x60 = 0x200`); what fills
the untouched gaps (`+0x18`, `+0x28..+0x5f`) and when; who reads
`[block]` and `[block+8]` after the gate returns the block;
whether `[context+0xe0]` is an address cursor or a byte count
(the helper stores it verbatim, so it does not decide this);
`.bss` contents are runtime-filled and not readable from the
file, and nothing here depends on them.

No progress gate is requested by this packet. Next question
(#237): decode `0x63d94b0` end to end — what it does with the
gate block it receives as second argument from the driver, and
whether it is an alternate entry of the `0x63d94a0` completion
helper — this decides what the stamped block built here becomes
after the driver passes it on.
