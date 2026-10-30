# foundation: bind the node #94 shared read-lock helper at 0x358dcd0

- Component: `foundation`; bounded static function validation.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. #115 and visor not covered.
- Claim status: byte/record observations with an inferred parking_lot
  read-guard label; no reconstruction, no gate request.
- Scope: body `0x358dcd0..0x358de41` (369 bytes), FDE record, two dependency
  Locations (std once.rs and parking_lot raw_rwlock.rs), the descriptor
  struct relocation, the 1e9-nanosecond immediate, six GOT-mediated call
  targets, and the 952-site / 358-function census. Excluded: the callees'
  internals, all callers, #115, visor.

## Question

What is the helper behind GOT slot `0x5773190` — the callee the fees body
(#109) and hundreds of other bodies call around their guarded state?

## Reproduce

```sh
python3 tools/elf_index.py --release 94
python3 tools/readlock_static.py --output work/readlock-record.json
diff work/readlock-record.json research/work-items/readlock-helper-94/observed/records.json
python3 -m unittest discover -s tests -p test_readlock_static.py -v
```

The tool authenticates size/SHA-256, then checks the exact FDE and body
bytes, both Locations through relocations, the descriptor struct relocation,
six call sites with their GOT targets, the 1e9 immediate, and the census
(grouped via the repository's unwind index). Disassembly rendered with
capstone 5.0.7 (labeled); byte records authoritative. Windows 10 22H2,
Python 3.11.9.

## Observations

The 369-byte body carries two dependency anchors: std
`sync/once.rs:219:20` under rustc commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1` and
`parking_lot-0.12.3/src/raw_rwlock.rs:1145:45` — pinning both the toolchain
and the locking crate version. The body tests a state word, consults a
descriptor struct at `0x5786278` (relocation-bound to `0x35ab620`), and on
contention takes a path with the `0x3b9aca00` (1e9 nanoseconds) immediate
before parking — consistent with parking_lot's reader parking flow (inferred
label). Six GOT-mediated targets include the parking wrapper `0x4e0d2c0`
(twice) and panic machinery `0x157b480`/`0x157b63b`.

Census over the complete `.text`: the single GOT slot `0x5773190` receives
952 `ff 15` call sites across 358 distinct FDE-indexed functions — by site
count the most-shared helper measured in this series (the Time Sub helper
has 72 sites / 60 functions).

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (369 bytes), 1 FDE, 2 Locations, 1 descriptor relocation, 6 call
  targets, 1 immediate; census denominator is the complete `.text` for
  slot-targeted `ff15`.
- 8 tests pass. Author rerun, not independent peer review.
- Unknowns: the callees' semantics and what state each of the 358 callers
  guards. No execution, Rust build, hosted CI, or gate.

Next: descriptor target `0x35ab620` and one representative caller family.
