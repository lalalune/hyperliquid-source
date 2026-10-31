# RE-001: bind the node #94 channel body 0x4391840 at 0x4391840

- Component: `net_utils`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x4391840..0x4392387` (2887 bytes), its
  FDE record, all 72 verified branch destinations, all 23 direct
  `e8` call sites with destinations, all 26 GOT-mediated call sites with
  slots, every panic Location (4), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The path-evidence map anchors 3 source file(s) (net_utils/channel.rs, node/channel.rs, node/consensus/server.rs) to this body; what does it carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/channel-4391840_static.py --output work/channel-4391840-record.json
diff work/channel-4391840-record.json research/work-items/RE-001-channel-4391840-94/observed/records.json
python3 -m unittest discover -s tests -p test_channel-4391840_static.py -v
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

Reached per the whole-.text census in records.json. 4 panic Locations: naive/datetime/mod.rs:1631, task.rs:2483, task/__internal/atomic_waker.rs:311, time.rs:429. 26 GOT-mediated calls (the chrono NaiveTime shift helper (chrono-shift packet) via GOT 0x576e8a8; the chrono NaiveDate shift helper (chrono-shift packet) via GOT 0x576e8b0. slots and relocation targets in records.json) and 23 direct e8 calls; 72 verified branch destinations. All values are byte/record observations.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (2887 bytes), 1 FDE record, 72
  branch destinations, 23 direct call sites, 26 GOT-mediated call
  sites, 4 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
