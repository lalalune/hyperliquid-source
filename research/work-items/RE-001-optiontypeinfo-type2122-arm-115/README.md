# RE-001: the OptionTypeInfo type-21/22 arm (node #115)

**Task:** RE-001. **Node:** #115, artifact `artifacts/node/115/hl-node`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`).

**Bounded question:** what does the type-21/22 arm of the OptionTypeInfo
apply (`0x60bedc0`) do, which entries can reach it, and what `Status` does
each path return? This resolves open unknowns 1, 3 and 4 left by PR #4311
(the verification gate); the verification C++ enum names remain open.

## What was pinned

- **The arm is the primary parse for types 21/22, not a fallback.**
  The apply's jump table at `0x9786b4` holds 25 int32 relative offsets;
  entries 17–22 all resolve to `0x60bf07e`, which does `sub $0x15; cmp $1;
  jbe 0x60bf1e0`. Types 17–20 fail that range test and take the verification
  error path; types above 24 bypass the table (`ja 0x60bf07e`). This corrects
  #4311's "fallback after a failed primary parse" phrasing.
- **Type 21 has no entries; type 22 has 15** (3 DBOptions, 12 CFOptions).
  See `type22-entries.tsv`.
- **Only 10 of the 15 can reach the arm.** The arm runs only when the
  record's parse manager (`record+0x18`) is zero. Five entries install a
  custom parse pair and never reach it: `statistics`, `wal_filter`,
  `file_checksum_gen_factory` (DB special pairs) and `prefix_extractor` /
  `memtable_insert_with_hint_prefix_extractor` (the type-22 helper
  `0x6083a90`, which also forces flags `0x400`). The other 10 — the six CF
  direct-write entries and the four factory-builder entries — have empty
  parse functions. See `reachability.tsv`.
- **The arm never synthesizes a verification error.** Its only arm-level
  errors are the two `kNotFound` messages: `"Could not find configurable:
  <name>"` (null object, literal `0x43fb8a`) and the base-null
  `"Could not find option"` (`0x44e056`). A failure `Status` is whatever the
  callee returned, propagated verbatim.
- **The `=` path (`0x6099e70`):** ConfigOptions copy, `find("=")`, then the
  map parser `0x60c1190` (`"k=v;k=v"` or `"{k=v;k=v}"`; braces stripped),
  whose three malformed-input outcomes are all `kInvalidArgument` (code 4):
  `"Mismatched key value pair, '=' expected"`, `"Unexpected char in key"`,
  `"Empty key found"`. On a good map it calls ConfigureOptions (slot `0x48`,
  `0x609d0e0`) via `0x6097110`. With no `;` and no `=`, it calls the object's
  slot `0x40` unless that is the empty-Status stub `0x60956f0`, then
  PrepareOptions (slot `0x28`, `0x6095e70`) unless `ConfigOptions+0x3` is 0.
- **The no-`=` path (`0x609ba30` → `0x609b8a0`):** GetOptionName (slot
  `0x68`, `0x609d980`; return ignored), a scan of the options vector at
  `[field+8]` via the nested-key lookup `0x60ba0b0`, and `0x609b700`:
  type 22 delegates to `0x609a740`; types 19/21/22 with a name match call
  ParseOption (slot `0x50`, `0x60986b0`); otherwise `kNotFound "Could not
  find option: <name>"` (`0x43e863`).
- **The custom parse (`0x60809e0`):** name `"id"` with an empty value resets
  the shared pointer to null and returns OK; anything else delegates to
  `0x61ca3d0`.
- **The serializer's type-21/22 arms (`0x60bb9a0`, entries `0x60bbbf0` /
  `0x60bba43`):** the same flags gate (deref first, null object emits
  nothing or the `.bss` string at `0x6508980`); otherwise the emitted form
  is the object's slot-`0x78` name, or `name;options` via `0x60971c0`.
  A failed per-type serialize is `kNotSupported` (code 3)
  `"Cannot serialize option: <name>"` (`0x4373cf`).
- **Flags survey:** across all 214 mapped entries only type-22 entries
  carry flags bits `0x200`/`0x400`/`0x800`; none carries `0x800`.

## Evidence

- `records.json` — semantic records only (no per-instruction mnemonic list).
- 17 whole-function verbatim objdump excerpts; the apply and serializer
  excerpts are re-shipped byte-identical from #4311.
- `type22-entries.tsv` (15 rows), `reachability.tsv` (15 rows),
  `literals.tsv`, `frames.txt` (FDE ranges).
- `census.py` (44 binary-grounded checks), `export_excerpts.py`,
  `gen_records.py`, `verify.py`, `MANIFEST.sha256`.
- Model + tests: `tools/optiontypeinfo_type2122_arm_115.py`,
  `tests/test_optiontypeinfo_type2122_arm_115.py` (34 tests).

## Verification

```
python3 research/work-items/RE-001-optiontypeinfo-type2122-arm-115/verify.py
# verify: ALL CHECKS PASSED
python3 -m pytest tests/test_optiontypeinfo_type2122_arm_115.py -q
# 34 passed
```

## Open unknowns

- C++ enum names for verification 0–5 (behavior pinned, names not).
- `0x609a740` internals (type-22 apply delegate), `0x61ca3d0` internals
  (custom-parse delegate), `0x60971c0` internals (serializer helper).
- `ConfigOptions+0x4` / `+0x28` C++ field names (serializer gates).
- The `.bss` string at `0x6508980` emitted for a null type-22 object.
- Whether any OptionTypeInfo map beyond DBOptions/CFOptions has type-21/22
  entries.
- `0x60ba0b0` nested-key lookup internals; record `+0xb8` as the name
  string (unverified inference).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. All claims are from
static disassembly of `work/hl-node-115.bin` (hash verified against
`provenance/artifacts.json`) plus `readelf` FDE data. `make verify` /
`make test` / `make catalogue-check` were not run here; they need a tooled
environment.
