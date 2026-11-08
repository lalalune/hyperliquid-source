# RE-001: pin node #115 the ROT13BlockCipher ':'-split factory 0x5ff7120 and its block_size option map

## Question

What does the 2-site RegisterOptions host `0x5ff7120` build, which option
group does it register, and what does the shared map `0x65052c0` hold?
This cluster is 2 of the 32 unanalysed RegisterOptions sites in #4372's
37-site census.

## Answer (one paragraph)

The host is the `ROT13BlockCipher` `:`-split factory: it builds a 0x28-byte
`rocksdb::(anonymous namespace)::ROT13BlockCipher` (vtable `0x64cfea0`),
registers the group `ROT13BlockCipherOptions` with the static map
`0x65052c0` at both RegisterOptions sites, and the map holds exactly one
entry, `block_size` (type 22, verification 1, flags `0x400`, offset 0),
inserted by the static initializer `0x5ff7c90`. The spec `ROT13` (no
colon) yields the default block size 32; `ROT13:N` parses N base-10 via
the stoul wrapper `0x61d1540`; empty or non-numeric suffixes are rejected.
The transform (vtable slots 20/21, identical bodies) adds 13 (mod 256) to
each of the first N bytes with no alphabet check and no wraparound at 'z'
-- it is byte-wise +13, not letter-ROT13 and not self-inverse.

## Evidence

- `records.json` -- semantic records only (no per-instruction mnemonic
  list): factory, group, map, vtable, suffix parser, cited context, open
  unknowns.
- `fn-*.objdump.txt` -- whole-function objdump excerpts (repo-relative
  binary path) for the factory, the initializer, the insert helper, the
  stoul wrapper, both destructors, Name / slot 19 / slots 20-21, the
  string ctor, and the two record move ctors.
- `callers.tsv` -- every lea reference to the map, the vtable, and the
  factory, with the enclosing FDE.
- `maps.tsv` -- the three maps the initializer builds (`provider`,
  `block_size`, `cipher`), one entry each.
- `vtables.tsv` -- all 22 slots of the ROT13 vtable.
- `literals.tsv` -- the string/pack literals behind the claims.
- `frames.txt` -- the FDE extents for every pinned window.
- `census.py`, `export_excerpts.py`, `gen_records.py` -- the generators
  for the tables, excerpts, and records above.
- `verify.py` -- self-checks; run it from the repo root:
  `python3 research/work-items/RE-001-rot13-factory-115/verify.py`
  (artifact digest, manifest, excerpt regeneration byte-identical to
  fresh objdump, FDE identities, raw-binary spot bytes, literals, lea
  census, semantic-only records, model tests). ALL CHECKS PASSED (82/82).

## Model and tests

- `tools/rot13_factory_115.py` -- `parse_block_size`, `rot13_block`,
  `Rot13BlockCipher`, `create_cipher` (replace semantics).
- `tests/test_rot13_factory_115.py` -- 14 tests, all passing.

## Open unknowns

- The factory's first argument (rdi, never read) -- C++ role open.
- The `*out_slot` container type (unique_ptr vs raw field) -- open.
- The registry builder `0x5ff88c0`'s exact C++ name -- open.
- The stoul wrapper's exact accepted trailing-character set -- open.
- Which record std::function member each GOT callback pair fills.
- The sibling 0x38-byte factories `0x5ff6a00` / `0x5ff6d60` and the small
  host `0x5ffabd0` -- separate work, not pinned here.
- Whether BlockCipher adds virtuals of its own: the D2 destructor
  restores the Configurable vtable `0x64d3430` directly.

## Artifact

`work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(matched against `provenance/artifacts.json`, entry
`artifacts/node/115/hl-node`).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the check is
static-only: objdump excerpts, raw-byte spot checks, and the Python
model. `make verify test catalogue-check` was not run -- this packet adds
no tooling and touches no catalogue or generated progress records.
