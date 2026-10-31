# RE-001: bind the node #94 clearinghouse body 0x36fe830 at 0x36fe830

- Component: `l1`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x36fe830..0x36ff3be` (2958 bytes), its
  FDE record, all 96 verified branch destinations, all 13 direct
  `e8` call sites with destinations, all 14 GOT-mediated call sites with
  slots, every panic Location (4), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The path-evidence map anchors 5 source file(s) (l1/clearinghouse/clearinghouse.rs, l1/clearinghouse/oracle/oracle.rs, l1/perp_meta.rs) to this body; what does it carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/clearinghouse-36fe830_static.py --output work/clearinghouse-36fe830-record.json
diff work/clearinghouse-36fe830-record.json research/work-items/RE-001-clearinghouse-36fe830-94/observed/records.json
python3 -m unittest discover -s tests -p test_clearinghouse-36fe830_static.py -v
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

Reached per the whole-.text census in records.json. 4 panic Locations: clearinghouse/clearinghouse.rs:1500, clearinghouse/clearinghouse.rs:1508, clearinghouse/oracle/oracle.rs:197, perp_meta.rs:194. 14 GOT-mediated calls (the shared read-lock helper 0x358dcd0 (readlock packet) via GOT 0x5773190. slots and relocation targets in records.json) and 13 direct e8 calls; 96 verified branch destinations. All values are byte/record observations.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (2958 bytes), 1 FDE record, 96
  branch destinations, 13 direct call sites, 14 GOT-mediated call
  sites, 4 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
