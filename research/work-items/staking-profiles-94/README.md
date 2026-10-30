# staking: bind node #94 validator_profiles_at_epoch at 0x3366580

- Component: `staking` (first binding); bounded static function validation.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. #115 and visor not covered.
- Claim status: byte/record observations with inferred labels; no
  reconstruction, no gate request.
- Scope: the body `0x3366580..0x3366b60` (1,504 bytes), FDE record, epoch
  BTreeMap lookup, validator iteration, delegator-balance checked sum, the
  BTreeSet duplicate guard and its assert panic, four stdlib panic Locations
  carrying the rustc build hash, result tags, and the call census. Excluded:
  the set-guard callee `0x3399380`, the caller `0x3369db0..0x336a360`, the
  panic callees, #115, visor.

## Question

What does the code bound to `l1/src/staking.rs` compute, and does the binary
match the reference sketch's error handling?

## Reproduce

```sh
python3 tools/staking_profiles_static.py --output work/staking-record.json
diff work/staking-record.json research/work-items/staking-profiles-94/observed/records.json
python3 -m unittest discover -s tests -p test_staking_profiles_static.py -v
```

Python 3.10+, verified Git LFS inputs. The tool authenticates size/SHA-256,
then checks the exact FDE and body bytes, sixteen structural windows, the
assert message/Location/panic callee, three stdlib Locations through their
relocations, four noreturn call sites, the set-guard direct call, and the
whole-`.text` census. Disassembly rendered with capstone 5.0.7 (labeled);
byte records authoritative. Windows 10 22H2, Python 3.11.9.

## Observations

The body walks an epoch-keyed BTreeMap (node count word `+0x21a`, children
`+0x220`); a miss returns result tag `0x97` (epoch state missing). Found
states iterate validators at a 64-byte stride, copying profile fields from
entry offsets `+0x18/+0x28/+0x2c/+0x3c`. Each delegator map (count word
`+0x13e`, values base `+0x148`) is summed with two checked u64 adds whose
carry branches both land on one noreturn site. A direct call to
`0x3399380` guards BTreeSet insertion: the duplicate outcome routes to the
assert panic `assertion failed: profiles.insert(validator_profile)`
(`staking.rs:243:17`, message at `0x58bfde`, panic callee `0x157b7f0`) —
corroborating the reference's documented duplicate-profile invariant. Success
writes result tag `0x186` with the epoch and profile payload.

Four noreturn sites carry stdlib Locations under rustc commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`:
`alloc/src/collections/btree/navigate.rs:534:47` (twice) and `:161:36` (once)
through panic callee `0x157a9f0`, and `core/src/iter/traits/accum.rs:204:1`
through `0x157b480` — the landing site of both checked-add carries. This
yields a build-provenance anchor (the rustc hash) and a divergence: the
binary panics on delegator-sum overflow, while the reference sketch proposes
`checked_add().ok_or(ArithmeticOverflow)` returning an error; the bytes do
not support the sketch's error variant on this path.

Census: GOT slot `0x5775c78`, one indirect caller `0x3369dd1` inside
`0x3369db0..0x336a360`; zero direct `e8`/`lea` references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (1,504 bytes), 1 FDE, 16 windows, 1 assert anchor, 3 stdlib
  Locations, 2 panic callees, 1 direct guard callee, census — denominators
  are the explicit lists above.
- 9 tests pass. Author rerun, not independent peer review.
- Unknowns: set-guard callee internals, the caller's role, panic callee
  semantics. No execution, Rust build, hosted CI, or gate.

Next: bind the set guard `0x3399380` and the caller `0x3369db0..0x336a360`.
