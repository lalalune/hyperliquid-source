# fees: bind node #94 fee computation at 0x37153f0

- Component: `fees` (first binding); bounded static function validation.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. #115 and visor not covered.
- Claim status: byte/record observations with an inferred fee-computation
  label; no reconstruction, no gate request.
- Scope: body `0x37153f0..0x3715e8b` (2,715 bytes), FDE record, five source
  Locations across five files, six inlined quantity-construction sites with
  saturating tails, the fee-rate float constants and division-by-10 magic
  pair, the panic pair, and the three-caller census. Excluded: the helper
  `0x358dcd0`, the six direct callees, the three callers, #115, visor.

## Question

What does the code bound to `l1/src/fees/compute.rs` compute, and which
quantity machinery does it reuse?

## Reproduce

```sh
python3 tools/fees_compute_static.py --output work/fees-record.json
diff work/fees-record.json research/work-items/fees-compute-94/observed/records.json
python3 -m unittest discover -s tests -p test_fees_compute_static.py -v
```

Python 3.10+, verified Git LFS inputs. The tool authenticates size/SHA-256,
then checks the exact FDE and body bytes, four instruction windows, five
Locations through relocations, five float constants, six quantity sites with
their saturating tails, three GOT slots, and the census. Disassembly rendered
with capstone 5.0.7 (labeled); byte records authoritative. Windows 10 22H2,
Python 3.11.9.

## Observations

The body carries Locations for five files in one function:
`fees/compute.rs:50:42`, `perp_meta.rs:194:38`, `qtys/impl_ntl.rs:664:1` (six
inlined sites), `qtys/mod.rs:843:1`, and `core/src/num/mod.rs:320:5` under
rustc commit `e408947bfd200af42db322daf0fadfe7e26d3bd1` — the same build hash
as the staking and vault packets.

Six sites call the shared lock helper `0x358dcd0` through GOT `0x5773190` (a parking_lot-anchored read-guard acquisition; the fees body holds `impl_ntl.rs:664:1` Locations for the guarded conversions) with
the pair `(0, &impl_ntl.rs:664:1 Location)`; two sites show register spills
between the arguments and the call. Each is followed by an `add` whose carry
selects the `-1` sentinel through `cmovae` — the saturating conversion
pattern. The float block centers on a one-tenth fee scale: `0.1` at
`0x20a880`, `1.0` at `0x20a730`, i64 range bounds as f64
(`0x20a7f0`/`0x20a2c8`/`0x20acb8`), and a division-by-10 magic pair
(`0x0147ae147ae147ae` / `0xfeb851eb851eb852`) — inferred label: fee-tier
computation converting an f64 rate into integer quantity units.

A noreturn pair loads the perp_meta and fees Locations through panic-display
`0x157a9f0`; the tail lands in panic-fmt `0x157aa10` and `0x157b4c0`.

Census: GOT slot `0x5774560`, three indirect callers (`0x24fc475`,
`0x4329c95`, `0x432a525`), zero direct `e8`.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (2,715 bytes), 1 FDE, 4 windows, 5 Locations, 6 quantity sites,
  5 constants, 3 GOT slots, census — denominators are the explicit lists.
- 8 tests pass. Author rerun, not independent peer review.
- Unknowns: the helper's conversion semantics, the six direct callees, the
  three callers. No execution, Rust build, hosted CI, or gate.

Next: the shared lock helper `0x358dcd0` itself (parking_lot 0.12.3 raw_rwlock.rs + std once.rs Locations), which also dominates the vault packet's call sites.
