# RE-001: bind the node #94 hour body 0x220bed0 at 0x220bed0

- Component: `base`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x220bed0..0x220c477` (1447 bytes), its
  FDE record, all 39 verified branch destinations, all 7 direct
  `e8` call sites with destinations, all 28 GOT-mediated call sites with
  slots, every panic Location (4), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The path-evidence map anchors 4 source file(s) (base/hour.rs, base/time.rs, l1/abci/engine.rs) to this body; what does it carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/hour-220bed0_static.py --output work/hour-220bed0-record.json
diff work/hour-220bed0-record.json research/work-items/RE-001-hour-220bed0-94/observed/records.json
python3 -m unittest discover -s tests -p test_hour-220bed0_static.py -v
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

Reached per the whole-.text census in records.json. 4 panic Locations: exchange/exchange.rs:601, hour.rs:12, naive/date/mod.rs:2061. 28 GOT-mediated calls (the chrono NaiveDate shift helper (chrono-shift packet) via GOT 0x576e8b0. slots and relocation targets in records.json) and 7 direct e8 calls; 39 verified branch destinations. All values are byte/record observations.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (1447 bytes), 1 FDE record, 39
  branch destinations, 7 direct call sites, 28 GOT-mediated call
  sites, 4 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
