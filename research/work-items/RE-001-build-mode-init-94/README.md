# RE-001: bind the node #94 build-mode initializer 0x143ef30

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus the memchr no-false-negative
  identity; the build-mode label follows from the project-source panic
  Locations; no reconstruction, no gate request.
- Scope included: the 1463-byte body `0x143ef30..0x143f4e7` (FDE `0xfcef20`),
  fifteen anchors, five lea targets (the assertion message, both
  `build_mode.rs` Locations, both `memchr.rs` Locations), seven GOT-mediated
  callees against relocations, the `/cham/` prefix and assertion strings, the
  memchr word-scan identity, and the reachability census.
- Scope excluded: the cell and getter (bound in
  `RE-001-crossroads-callees-94`), the entry points `0x4edce70`/`0x4f100b0`,
  the format and panic callees, #115, visor.

## Question

The lazy getter's cold path passes an initializer into the Once machinery:
what does `0x143ef30` compute?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/build_mode_init_static.py --output work/bmi-record.json
diff work/bmi-record.json research/work-items/RE-001-build-mode-init-94/observed/records.json
python3 -m unittest discover -s tests -p test_build_mode_init_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact body and FDE,
fifteen anchors, the five lea targets, both string constants, all five
Location structs (paths, lines, columns), the seven call sites against
relocations, the assert length operand, the memchr identity, and the
reachability census. Disassembly text in `observed/` was rendered with
capstone 5.0.7 and labeled as such; byte records are authoritative.
Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The body is the project-source function behind the ship-complete cell: its
panic Locations are `hl/code_Mainnet/base/src/build_mode.rs:29:17` (the
assertion `assertion failed: !arg.ends_with('/')`) and `:32:26` (an error
path through the str-error callee). It compares the six-byte prefix
`/cham/`, rejects a `--` prefix (word compare `0x2d2d`), scans for `/` with
an inlined memchr built on the constant triple `0x2f2f2f2f2f2f2f2f`,
`0x0101010101010100` and `0x8080808080808080` (Locations
`core/src/slice/memchr.rs:160:9` and `:132:30` under the shared rustc hash),
guards a UTF-8 boundary with `0xc0`, reverses over `-` (`0x2d`) through the
scan callee, allocates through the entry point shared with the allocator
shim packet, formats through `0x1344760`, and terminates its panic block
with `ud2`. The memchr word predicate is validated as no-false-negative:
every needle placement flags. Reachable only through the cell's initializer
slot: zero direct, GOT-mediated or `lea` code references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (1463 bytes) + FDE, 15 anchors, 5 lea targets, 2 strings, 5
  Location structs, 7 call sites against relocations, 1 identity;
  census denominator is the complete `.text` for `e8` / `ff 15` / `lea`
  encodings.
- 6 tests pass (record match, project anchor, memchr no-false-negative,
  memchr Locations, reachability, body mutation control). Author rerun, not
  independent peer review.
- Unknowns: what the entry points return, the full argument grammar, and the
  exact string the cell materializes. The label follows from the Locations.
  No execution, Rust build, hosted CI, or gate.

Next question: the entry points `0x4edce70` and `0x4f100b0`, and the two
large crossroads callees `0x143d010` and `0x4b31e70`.
