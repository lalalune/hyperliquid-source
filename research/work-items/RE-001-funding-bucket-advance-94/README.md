# RE-001: three funding-labelled bucket-advance fragments

- Component: `foundation`, bounded shared guard/counter mapping; no progress gate.
- Target: node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its `base/err_dur_guard.rs` supplied three address leads only. No inferred
  implementation was copied. Its names/types are not accepted as binary facts.
- Question: which quotient width, previous-bucket update predicate and outgoing
  work paths do those three actual extents implement?
- Status: instruction/data observations, bounded architectural fragment model,
  unresolved ownership and complete behavioral semantics.

## Reproduce

Materialize pinned LFS captures and submodules. From repository root:

```sh
python3 -B tools/funding_bucket_static.py --output work/funding-bucket-94
python3 -B tests/test_funding_bucket_static.py
cmp work/funding-bucket-94/records.json research/work-items/RE-001-funding-bucket-advance-94/records.json
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-funding-bucket-advance-94/MANIFEST.sha256
```

Python3.12.14 / macOS26.4 arm64 / GNU objdump and readelf2.47.20260726. The
checker uses the standard library and existing repository ELF/FDE parsers.
It authenticates one immutable byte string, gives a private copy of the same
bytes to native decoders, confirms all three FDEs independently with readelf
and checks every interpreted operand starts at an objdump instruction.
A separate observed Capstone5.0.6 cross-check decoded 88 instructions and all
387 bytes in each extent. Capstone is not required to reproduce the packet.
No captured target or service runs; all comparisons are static.

## Observations

Addresses are linked ELF VAs; each retained range and data record includes
its source-file offset. No loader base or inferred provider rebase is added.

| FDE extent (exclusive end) | Interval field | Previous-bucket field | Outgoing direct call |
| --- | --- | --- | --- |
| `0x2702420..0x27025a3` | `object+0x37d0` | `object+0x37d8` | `0x222af40` |
| `0x4ceec70..0x4ceedf3` | `object+0x37d0` | `object+0x37d8` | `0x4713110` |
| `0x4ceee00..0x4ceef83` | `object+0x4250` | `object+0x4258` | `0x4715760` |

- Denominator: exactly three FDE-described extents / 1,161 captured bytes,
  selected from the three leads, not all bucket guards or funding handlers.
  All three load the exact label `update_funding_rates`; this is not proof
  of the callees' complete funding semantics or source-level ownership.
- A shared calendar-derived prefix ends with `xor eax,eax; test rcx,rcx;
  cmovg rax,rcx` at offset `+0xbb`. The fragment analyzed here begins at
  that signed-positive clamp. Calendar correctness and its valid input
  representation remain outside this packet; the earlier millisecond/Chrono
  research is not counted again as a new recovery.
- At `+0xc4`, each extent loads a 64-bit divisor from its interval field.
  `(RAX | RCX) >> 32` selects the 32-bit division path only when both operands
  fit in unsigned 32 bits. Both paths clear EDX before `div ecx` / `div rcx`.
  For a nonzero divisor these encode the same unsigned quotient. Neither
  path inserts a divisor clamp after that load. The reference's `.max(1)`
  behavior is therefore not evidenced inside these extents. Whether object
  construction guarantees a nonzero divisor is unresolved; no reachable
  crash, vulnerability or caller-precondition claim is made.
- Both paths compare the quotient against the old field with an unsigned
  comparison, write only for strict increase, and preserve the same old
  register for the subsequent comparison. `seta [rsp+0x60]` materializes
  strict `new_bucket > old_bucket`, including false on equality. The 32-bit
  path joins the same store/comparison blocks; it is not an independent
  differently-rounded operation.
- A 16-byte load from `0x205e70` is copied to `[rsp+0x50]`. Its raw bits decode
  as f64 values 0.01 and 0.05. The raw bytes and destination are observed;
  naming these source-level struct fields or assuming their semantic types
  from the inferred reference is not justified here.
- Each extent supplies its label, stack fields and object subfield addresses
  before its one distinct direct call. Raw disassembly preserves all of
  these extra argument setup instructions. Transitive helper recovery and
  side-effect semantics of those outgoing work functions remain open.

`records.json` preserves all three bodies, separate hashes and raw operands.
No byte masking, relocation normalization, reconstructed Rust match count or
binary transplantation is used. FDE extents are not asserted to be a complete
validated function inventory.

## Controls and limitations

Five tests cover actual input bindings, deterministic native regeneration,
21 instruction corruptions across all three copies, and three literal/data
corruptions below the digest gate. They reject changed width selection,
divisor register, signed/unsigned predicate, state store, flag materialization,
32-bit join and outgoing call; this exercises actual interpretations rather
than only input hashing. Actual captures and prior research remain unchanged.

The fragment model is checked over 192 explicit mathematical cases spanning
0/1, millisecond boundaries, `2^32` width transitions, `i64::MAX` dividend,
large nonzero divisors and unchanged/greater previous buckets. This is not
an execution comparison, not calendar validation and not a target-equivalence
denominator. Invalid model inputs, including zero divisors, are excluded
explicitly rather than inventing observed handling for them.

No implementation or accepted component gate changes. Next question: recover
one object's interval initializer and callers to determine its actual
preconditions, then trace one outgoing work function under RE-001.
