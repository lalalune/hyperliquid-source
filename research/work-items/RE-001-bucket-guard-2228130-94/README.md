# RE-001: bind the node #94 bucket_guard body 0x2228130 at 0x2228130

- Component: `base`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x2228130..0x2228a0d` (2269 bytes), its
  FDE record, all 67 verified branch destinations, all 12 direct
  `e8` call sites with destinations, all 23 GOT-mediated call sites with
  slots, every panic Location (3), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The path-evidence map anchors 4 source file(s) (base/bucket_guard.rs, l1/asset/pdi.rs, l1/clearinghouse/oracle/oracle.rs) to this body; what does it carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/bucket-guard-2228130_static.py --output work/bucket-guard-2228130-record.json
diff work/bucket-guard-2228130-record.json research/work-items/RE-001-bucket-guard-2228130-94/observed/records.json
python3 -m unittest discover -s tests -p test_bucket-guard-2228130_static.py -v
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

Reached per the whole-.text census in records.json. 3 panic Locations: asset/pdi.rs:30, clearinghouse/oracle/oracle.rs:202, naive/datetime/mod.rs:1631. 23 GOT-mediated calls (the chrono NaiveTime shift helper (chrono-shift packet) via GOT 0x576e8a8; the chrono NaiveDate shift helper (chrono-shift packet) via GOT 0x576e8b0. slots and relocation targets in records.json) and 12 direct e8 calls; 67 verified branch destinations. All values are byte/record observations.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (2269 bytes), 1 FDE record, 67
  branch destinations, 12 direct call sites, 23 GOT-mediated call
  sites, 3 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
