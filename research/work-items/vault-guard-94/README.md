# vaults: bind node #94 valuation guard at 0x395b3a0

- Component: `vaults` (first binding); bounded static function validation.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. #115 and visor not covered.
- Claim status: byte/record observations with an inferred valuation-guard
  label; no reconstruction, no gate request.
- Scope: body `0x395b3a0..0x395bdc3` (2,595 bytes), FDE record, the
  `l1/src/vault/mod.rs:407:58` Location, the reused stdlib navigate.rs
  Location, eight float-guard instruction windows, three shared f64
  constants, the noreturn panic tail, and the census. Excluded: the six
  helper callees, the four callers' bodies, #115, visor.

## Question

What does the code bound to `l1/src/vault/mod.rs` around line 407 do, and
which shared constants and panic machinery does it use?

## Reproduce

```sh
python3 tools/vault_guard_static.py --output work/vault-record.json
diff work/vault-record.json research/work-items/vault-guard-94/observed/records.json
python3 -m unittest discover -s tests -p test_vault_guard_static.py -v
```

Python 3.10+, verified Git LFS inputs. The tool authenticates size/SHA-256,
then checks the exact FDE and body bytes, eight instruction windows, both
Locations through relocations, the noreturn tail, three f64 constants, three
GOT slots, and the census. Disassembly rendered with capstone 5.0.7
(labeled); byte records authoritative. Windows 10 22H2, Python 3.11.9.

## Observations

The body centers on an f64 range/validation block: three divisions by the
shared `1e6` constant at `0x20ae60` — the same constant the Time Sub helper
divides by — comparisons against `i64::MIN`/`i64::MAX` as f64 at
`0x20acb8`/`0x20a7f0`, and `ucomisd reg,reg` NaN self-checks, characteristic
of a seconds/microseconds conversion bounded to the i64 range (inferred
label: valuation guard). A BTreeMap walk shares the node layout seen in the
staking packet.

The tail is a two-stage noreturn sequence: `lea rdi` to the stdlib Location
`alloc/src/collections/btree/navigate.rs:161:36` (rustc commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, the same build hash as the
staking packet) then `lea rdi` to `l1/src/vault/mod.rs:407:58`, both through
panic-display callee `0x157a9f0`, with the final landing through
panic-fmt `0x157aa10` at GOT `0x576e048`.

Census: GOT slot `0x5774b48`, four indirect callers (`0x2736819`,
`0x395b1dc`, `0x4d4275c`, `0x4d46699`), zero direct `e8`.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (2,595 bytes), 1 FDE, 8 windows, 2 Locations, 3 constants, 3 GOT
  slots, census — denominators are the explicit lists above.
- 8 tests pass. Author rerun, not independent peer review.
- Unknowns: the six helper callees' semantics, the four callers, and what
  the guarded ratio represents. No execution, Rust build, hosted CI, or gate.

Next: the six helper callees (esp. `0x358dcd0`, called six times) and the
remaining three vault/mod.rs Locations at lines 520/528/529/621/626/742.
