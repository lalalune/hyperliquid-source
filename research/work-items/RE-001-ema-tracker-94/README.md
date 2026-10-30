# RE-001: bind the node #94 ema_tracker time-decayed update and its accessor assert

- Component: `foundation`; bounded static function validation under RE-001,
  which has no prerequisites. This is not completion of RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`. The
  reference `base/ema_tracker.rs` snapshot is a 35-line behavior sketch whose
  `0x4726a50` seed was already narrowed by the heartbeat-status packet
  (PR #22). Nothing was copied from it; labels below come from binary
  evidence.
- Claim status: observations with explicit inferred labels; no reconstruction,
  no gate request.
- Scope included: the update body `0x14791c0..0x1479329`, its FDE record, its
  four panic anchors, the two `ema_tracker.rs` Location structs, the
  `num/denom` accessor assert inlined at three consumer sites, and the single
  GOT-indirect caller. Scope excluded: semantics of the elapsed helper
  `0x1447130`, the libm `exp` implementation, the caller's window logic,
  heartbeat consumers' own logic, #115, and visor.

## Question

What does the node #94 code bound to `base/src/ema_tracker.rs` actually
compute, and where is the `num/denom` accessor assert shared?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.
The captured executable is only read as data; no command below launches it or
contacts a node or chain. `make doctor verify test catalogue-check` covers the
repository checks; the packet commands are:

```sh
python3 tools/ema_update_static.py --output work/ema-record.json
diff work/ema-record.json research/work-items/RE-001-ema-tracker-94/observed/records.json
python3 -m unittest discover -s tests -p test_ema_update_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record and
body bytes, every conditional branch destination, both path-string copies,
all four Location structs through their RELATIVE relocations, the three panic
messages with their `esi` lengths, the elapsed/panic/update GOT slots, the
`exp` GLOB_DAT symbol name, the `-0.0` xorpd mask and the shared `1.0`
constant, the three accessor sites, and a direct/lea/GOT-indirect call census.
Disassembly text in `observed/` was rendered with capstone 5.0.7 (Python
bindings) and labeled as such; the byte records are authoritative. Platform:
Windows 10 22H2, Python 3.11.9; no binutils was available, and no objdump
output is included.

## Observations

Function `0x14791c0..0x1479329` (361 bytes, FDE at `.eh_frame` VA `0xced520`,
sha256 `84d8647a...`), reached only through GOT slot `0x576f8f0` by a single
`ff 15` caller at `0x474fcac` inside `0x474fb90..0x474fcf0`; no direct `e8`
or `lea` reference exists anywhere in `.text`.

Struct offsets (observation from load/store operands only): `f64 @ +0x0`,
`f64 @ +0x8`, `f64 @ +0x10`, `{u64, u32} @ +0x18`. The two lanes are updated
as one `movupd` pair and the accessor sites divide lane0 by lane1, so the
inferred labels are `num @ +0x0` and `denom @ +0x8` (inferred, consistent with
the `self.denom` message below).

Update flow, per decoded instructions:

1. If the timestamp's low seconds dword at `+0x18` is zero, the interval is
   the shared constant `1.0` at `0x20a730` and the elapsed helper is skipped.
   This is a low-dword test only; a timestamp with zero low dword but nonzero
   high dword would also take this path (limitation, not a claim about
   reachable states).
2. Otherwise the helper at `0x1447130` (GOT slot `0x576e8c0`) is invoked on
   the two 12-byte timestamps with a `{line 38, column 1}` path descriptor;
   its f64 result must satisfy `assertion failed: self.0 >= 0.`
   (inlined `duration.rs:89:13`) or the panic path at `0x14792f7` runs.
3. `tau` (`f64 @ +0x10`) must satisfy `assertion failed: other.0 > 0.`
   (inlined `duration.rs:90:13`), enforced by `ucomisd`/`jbe` at `0x147924e`
   (NaN traps to the panic too).
4. `decay = exp(-dt / tau)`: negation by `xorpd` with the `-0.0` pair at
   `0x2082f0`, one `divsd`, then a call through the `exp` GLOB_DAT slot
   `0x576f8f8` (dynsym name verified as `exp`).
5. `decay` must satisfy `assertion failed: decay <= 1.` at
   `ema_tracker.rs:42:13` (`ucomisd xmm1, xmm0` / `jb` at `0x147927c`;
   unordered NaN takes the panic). The bound constant is the same shared
   `1.0`.
6. Lanes update: `num' = sample*dt + decay*num`, `denom' = dt + decay*denom`
   (`mulsd`/`unpcklpd`/`mulpd`/`addpd`/`movupd` at `0x1479293..0x14792b7`),
   then the 12-byte sample timestamp is copied to `+0x18`.

The accessor assert `assertion failed: self.denom > 0.` at
`ema_tracker.rs:59:13` (Location `0x566c5c0`, shared message at `0x21a843`)
is inlined at exactly three sites — `0x4726d1a` (inside the heartbeat-status
body already mapped by PR #22), `0x4879d9b` and `0x4879dc5` (both inside
`0x48797c0..0x4879e20`). Each divides the pair's lane0 by lane1 after a
nonzero check; NaN handling is by `ucomisd` equality branches.

A decay underflow to exactly `0.0` (large `dt / tau`) satisfies the single
`decay <= 1.` bound, so a fully decayed tracker is architecturally
acceptable; that is an arithmetic observation, not a claim about reachable
runtime states.

## Implementation and comparison

Not yet implemented: no reconstructed Rust is included, so no two-build
comparison, helper closure or normalization mask exists yet. The lane-update
identity was checked in Python IEEE-754 doubles over a bounded grid
(`tests/test_ema_update_static.py`), which validates the decoded operand
semantics, not target equivalence.

## Results and limitations

- 1 update body bound to digest (361 bytes), 1 FDE record, 4 panic anchors,
  2 Location structs, 2 path-string copies, 2 float constants, 4 GOT slots
  verified against relocation records; denominator for every count is the
  explicit list above.
- Call census: 0 direct `e8`, 0 `lea`, 1 GOT-indirect caller over the whole
  `.text` (byte-pattern scan, 70,370,352 bytes); the census is complete for
  those three encodings but not for other indirect-call forms.
- 14 tests pass: identity, FDE range/hash, branch-corpus semantics, three
  accessor-site controls, relocation/constant/message/path mutation
  controls. Author rerun, not independent peer review.
- Unknowns: semantics of the elapsed helper `0x1447130` (microsecond
  conversion and range clamping observed but not bound), the caller's
  window/epoch guard logic, and whether any other code updates the same
  struct through different bodies. No execution, Rust build, hosted CI, or
  progress/component gate is claimed.

Next question: bind the elapsed helper `0x1447130` (12-byte timestamp
difference to f64 seconds, with its range clamp and `{38,1}` descriptor), and
the caller's epoch/window guard at `0x474fb90`.
