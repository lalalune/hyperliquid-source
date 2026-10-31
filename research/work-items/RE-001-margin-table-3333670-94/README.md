# RE-001: bind the node #94 margin_table body 0x3333670 at 0x3333670

- Component: `l1`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x3333670..0x33337f9` (393 bytes), its
  FDE record, all 17 verified branch destinations, all 1 direct
  `e8` call sites with destinations, all 5 GOT-mediated call sites with
  slots, every panic Location (3), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The path-evidence map anchors 2 source file(s) (l1/clearinghouse/margin_table.rs, l1/qtys/impl_ntl.rs) to this body; what does it carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/margin-table-3333670_static.py --output work/margin-table-3333670-record.json
diff work/margin-table-3333670-record.json research/work-items/RE-001-margin-table-3333670-94/observed/records.json
python3 -m unittest discover -s tests -p test_margin-table-3333670_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record
and body bytes, every branch destination, every call site with its
destination or GOT slot, every Location struct through its relocation, and
the whole-`.text` census for `e8` and `lea` encodings. The tool's constant
tables were emitted mechanically from the authenticated binary by a
one-shot generator kept out of the packet. Disassembly text in `observed/`
was rendered with capstone 5.0.7 and labeled as such; byte records are
authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

Reached per the whole-.text census in records.json. 3 panic Locations: clearinghouse/margin_table.rs:107, collections/btree/navigate.rs:94, collections/btree/navigate.rs:95. 5 GOT-mediated calls (the shared read-lock helper 0x358dcd0 (readlock packet) via GOT 0x5773190. slots and relocation targets in records.json) and 1 direct e8 calls; 17 verified branch destinations. All values are byte/record observations.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (393 bytes), 1 FDE record, 17
  branch destinations, 1 direct call sites, 5 GOT-mediated call
  sites, 3 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
