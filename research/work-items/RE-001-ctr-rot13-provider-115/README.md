# RE-001: pin node #115 the CTR/ROT13 provider factories 0x5ff6a00 / 0x5ff6d60 and the CTREncryptionProvider holder 0x5ff6880

## Question

What do the two unanalysed RegisterOptions host clusters 0x5ff6a00 and
0x5ff6d60 build, which option groups do they register, and what is the
shared 0x30-byte object built by their common callee 0x5ff6880? Two of
the 32 unanalysed RegisterOptions sites in #4372's 37-site census, plus
the 0x5ff6880 host's own site.

## Answer (one paragraph)

Both factories build a 0x38-byte `_Sp_counted_ptr_inplace<ROT13BlockCipher>`
(an in-place shared_ptr control block whose ROT13 cipher sits at +0x10
with block_size 32 at +0x30) and a 0x30-byte CTREncryptionProvider holding
an aliasing shared_ptr to that cipher at +0x20/+0x28. The factory registers
the group "ROT13BlockCipherOptions" with the static map 0x65052c0 (one
entry, "block_size"); the provider init 0x5ff6880 registers the group
"Cipher" with the static map 0x6505280 (one entry, "cipher"). The "CTR"
factory 0x5ff6d60 builds the ROT13 provider only when the spec ends with
"://test"; otherwise it builds an empty Cipher holder (null cipher).
Replacing the provider in the out slot destroys the old one through its
vtable slot 1, guarded against the CTR deleting destructor 0x5ff30b0.

## Evidence

- `records.json` -- semantic records only (no per-instruction mnemonic
  list): the two factories, the holder init, the destructor, the
  "://test" gate, the groups/maps, the three vtables with typeinfo
  resolutions, the release helper, cited context, open unknowns.
- `fn-*.objdump.txt` -- whole-function objdump excerpts (repo-relative
  binary path) for the "1://test" factory, the holder init, the CTR
  destructor, the "CTR" factory, and the shared_ptr control-block
  release helper.
- `callers.tsv` -- every lea reference to the two maps, the provider
  map, the three vtables and the two factories, with the enclosing FDE.
- `maps.tsv` -- the three maps the initializer 0x5ff7c90 builds
  (provider, block_size, cipher), one entry each (pinned by #4389,
  re-verified here).
- `vtables.tsv` -- the in-place control-block vtable, the CTR provider
  vtable, and the Configurable base vtable, each with its typeinfo name
  resolved from .rela.dyn.
- `literals.tsv` -- the string/pack literals behind the claims.
- `frames.txt` -- the FDE extents for every pinned window.
- `census.py`, `export_excerpts.py`, `gen_records.py` -- the generators
  for the tables, excerpts, and records above.
- `verify.py` -- self-checks; run it from the repo root:
  `python3 research/work-items/RE-001-ctr-rot13-provider-115/verify.py`
  (artifact digest, manifest, excerpt regeneration byte-identical to
  fresh objdump, FDE identities, raw-binary spot bytes, literals, lea
  census, semantic-only records, model tests). ALL CHECKS PASSED.

## Model and tests

- `tools/ctr_rot13_provider_115.py` -- `create_provider_1_test`,
  `create_provider_ctr`, `destroy_provider`, `SharedPtr`,
  `InplaceRot13Control`, `CTREncryptionProvider`.
- `tests/test_ctr_rot13_provider_115.py` -- 12 tests, all passing.

## Open unknowns

- The exact C++ type of the factories' out parameter (raw double pointer
  vs smart-pointer out param) -- open.
- The first arguments of both factories (rdi/rsi, never read) -- C++
  roles open.
- The paired second function pointers in the registry entries (0x5fefa80
  for "1://test", 0x5fefa50 for "CTR", 0x5fefab0 for "ROT13") -- roles
  open.
- Why the test provider registers under the name "1://test" rather than
  a plain name -- open.
- Which host registers a group against the provider map 0x6505300 -- the
  only non-initializer lea reference is 0x5ff6763 in FDE
  0x5ff6690..0x5ff682e (census site 0x5ff677e); that host is not pinned
  here.
- The EncryptionProvider intermediate base: the destructor resets the
  vtable from CTREncryptionProvider straight to Configurable -- whether
  EncryptionProvider adds virtuals or members is open.
- The small host 0x5ffabd0's full dispatch (the non-"ROT13" path via
  0x60bb890 / 0x5ffa710) -- not pinned here.
