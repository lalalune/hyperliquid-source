# RE-001: bind the node #94 vault deposit body at 0x3956320

- Component: `vaults`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations only; labels stay inferred from
  the anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x3956320..0x3957bbb` (6299 bytes), its
  FDE record, all 195 verified branch destinations, all 15 direct
  `e8` call sites with destinations, all 39 GOT-mediated call sites with
  slots, every panic Location (5), and the whole-`.text` caller
  census. Scope excluded: every callee (bound separately or unbound), #115,
  visor.

## Question

The third unbound vault body from #102's series note (vault/mod.rs:520/528/529 anchor lines); what does the largest vault body carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/vault-deposit-body_static.py --output work/vault-deposit-body-record.json
diff work/vault-deposit-body-record.json research/work-items/RE-001-vault-deposit-body-94/observed/records.json
python3 -m unittest discover -s tests -p test_vault-deposit-body_static.py -v
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

Reached only through its own GOT slot (see records.json). Five panic Locations across std collections/btree/navigate.rs (161, 173, 534, 560). Thirty-nine GOT-mediated calls include the shared read-lock helper 0x358dcd0 through GOT 0x5773190 (the 952-site helper bound in the readlock packet) and the 0x54c8cb0 helper through GOT 0x576e010 that the statistics body also uses ten times; fifteen direct e8 calls.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (6299 bytes), 1 FDE record, 195
  branch destinations, 15 direct call sites, 39 GOT-mediated call
  sites, 5 panic Locations; census denominators are the complete
  `.text` for `e8` and `lea` encodings.
- 9 tests pass (retained record, FDE/body identity, branch table shape,
  Location table shape, size/SHA rejection, body/FDE mutation controls,
  Location mutation controls, relocation mutation controls, census). Author
  rerun, not independent peer review.
- Unknowns: the body's actual computation and all callee semantics. No
  execution, Rust build, hosted CI, or gate.
