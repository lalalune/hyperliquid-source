# RE-001: pin node #115 the ObjectRegistry registrar map: construction, layout, (non-)population, consumption, and destruction

## Question

Pin node #115's ObjectRegistry registrar map end-to-end — the static
init `0x620b470` that constructs the three build-info strings and
initializes the map in place, the map's `unordered_map` layout and node
layout, the string-install helper `0x5f204e0`, the map destructor
`0x620a500`, and the ctor replay loop — and answer #4015's open unknown:
which `(name, creator)` pairs populate the map before the first getter
call.

## Answer

NONE. No `(name, creator)` pair ever populates the map. The
whole-binary census finds exactly two `lea` sites for the map address
(the ctor `0x61f9234` and the static init `0x620b516`), zero stored
qword pointers, zero absolute immediates, and zero `RELATIVE`
relocation addends naming it. The map stays empty, the ctor replay loop
is vacuous, and registration happens only through direct `AddLibrary`
calls — TTL (`0x62069f0`, pinned by #4065) and encryption (`0x5ff88c0`,
pinned by #4028). The "populating static initializers" do not exist.

## What this packet pins

- The static init `0x620b470..0x620b57d` (catalogue
  `_GLOBAL__sub_I_build_version.cc`, 206/269 = 76.58% published-crate
  rebuild, `docs/PROGRESS.md` row 6219). Invoked once at startup via
  `.init_array` entry 166 (slot `0x63f3bf8`, `RELATIVE` reloc addend
  `0x620b470`). It constructs the three build-info `std::string`
  globals — git SHA `6a436150417120a3f9732d65a2a5c2b8d19b60fc` (40 chars),
  `rocksdb_build_git_tag:v8.1.1` (28), `rocksdb_build_date:2023-04-06
  16:38:52` (38) — registers each one's destructor
  (`std::string::~basic_string`, GOT `0x64ed5d8`) via `__cxa_atexit`,
  initializes the registrar map in place, and tail-registers the map
  destructor `0x620a500` for the map itself. All three literals exceed
  the 15-byte SSO limit, so all three are heap-allocated.
- The registrar map object at `0x6509540` (0x38 bytes): a
  `std::unordered_map` (`_Hashtable`), NOT the `std::map` #4015 labelled
  it. Empty state: buckets = `&_M_single_bucket` (`0x6509570`), bucket
  count 1, `before_begin` null, element count 0, max load factor 1.0f
  (`0x3f800000`), next resize 0, single bucket null.
- The registrar node (0x50 bytes, not the 0x48 #4015 recorded): `_M_nxt`
  `+0x00`, key `std::string` `+0x08`, creator `std::function` `+0x28`,
  and 8 trailing bytes at `+0x48` (the cached hash-code slot in this
  toolchain's `_Hash_node` layout; never read by any pinned routine,
  recorded as inference).
- The string-install helper `0x5f204e0..0x5f205c3`: `rdi` = string
  object, `rsi` = C string (null throws `std::logic_error`,
  "basic_string: construction from null is not valid"), `rdx` ignored.
  Length ≤ 15 takes the SSO path (length 1 has its own arm); longer
  takes `_M_create` + `memcpy`. 12 direct call sites binary-wide: the
  3 here plus 9 in three sibling static initializers
  (`periodic_task_scheduler.cc`, `__static_initialization_and_destruction_0v`,
  `persistent_stats_history.cc`).
- The map destructor `0x620a500..0x620a5bd`: walks the node chain from
  `map+0x10`, per node calls the creator's manager with op 3 (only when
  non-null), destroys the key string (heap buffer iff the pointer
  differs from the SSO buffer, sized `capacity+1`), frees the node with
  `operator delete(node, 0x50)`, then memsets the bucket array, zeroes
  the counters, and frees the bucket array only when it is not the
  inline single bucket. Zero direct callers: its address is taken once,
  by the `lea` at `0x620b55f`, for `__cxa_atexit`.
- The ObjectRegistry ctor `0x61f91b0..0x61f9277`, re-shipped
  byte-identical from #4015: zeroes the registry, seeds `libraries[0]`
  via vec-insert `0x5ff7960`, then walks the map chain calling
  `AddLibrary(this, node+0x08, node+0x28)` per node. Its sole direct
  caller is the getter at `0x61f9380`. Because the map is empty, the
  loop body never runs on this target.
- Relocations: `.init_array` `RELATIVE` addend `0x620b470` at
  `0x63f3bf8`; `__dso_handle` self-pointers at `0x64efa20` and
  `0x64fe448`; `GLOB_DAT` string dtor at `0x64ed5d8`.

## Corrections to #4015

- The map is a `std::unordered_map`, not a `std::map`.
- Nodes are 0x50 bytes, not 0x48 (the destructor's sized delete).
- The map object is 0x38 bytes, not 0x48.
- The open unknown "which (name, creator) pairs populate the map" is
  answered: none do.

## Evidence

- `records.json` — semantic records only (layout, init, helper, dtor,
  replay, census, relocations, literals, open unknowns). No
  per-instruction mnemonic list: instruction-level detail lives only in
  the verbatim objdump excerpts.
- `static-init-620b470.objdump.txt`, `string-assign-5f204e0.objdump.txt`,
  `map-dtor-620a500.objdump.txt`, `ctor-61f91b0.objdump.txt` — whole-function
  verbatim excerpts (GNU objdump 2.42). The static-init and ctor
  excerpts are byte-identical to the ones shipped by #4015, re-shipped
  with credit; the readings are new.
- `frames.txt` — the 5 FDEs (4 windows + the getter).
- `callers.tsv` — 18 verified sites (12 string-helper calls, 1 ctor
  call, 3 getter calls, 2 map lea sites).
- `relocations.txt` — the 4 relocation records above.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the generators and the checker (see `verify.py` for the check list).
- `tools/registrar_map_115.py` + `tests/test_registrar_map_115.py` —
  the Python model (20 checks) covering the empty-state invariants,
  the string SSO/heap/null arms, the seeded-chain replay and destroy,
  and the census constants.

## Verification

`python3 research/work-items/RE-001-registrar-map-115/verify.py`:
ALL CHECKS PASSED (digest vs provenance, manifest, excerpt
regeneration byte-for-byte, fixed samples + 3 seeded random gate spots
byte-for-byte vs fresh objdump and the raw binary, frames, census
reproduction, model constants, relocations, literals, 20 model tests).

Note the mnemonics in the excerpts (e.g. `endbr64`) are genuine
instructions present in the target binary, not placeholders: every
excerpt regenerates byte-for-byte from a fresh objdump run, and the
gate spots are verified byte-for-byte against the raw binary as well.

## Open unknowns

- The 8 trailing node bytes at `+0x48`: consistent with the cached
  hash-code slot, but no pinned routine reads them, so the role is
  layout inference, not observed use.
- The second `__dso_handle` slot at `0x64fe448`: which registration
  uses it is not pinned (this static init uses `0x64efa20`).
- The registry `+0x70..0x98` region (40 bytes) is still open (see
  #4015); this packet does not touch it.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the repo
gates (`make verify`, `make test`, `make catalogue-check`) cannot run
here; the packet's own `verify.py` and the model tests are the checks
that ran. The packet is evidence + a Python model, not a Rust
reconstruction, so it does not touch those gates.
