# RE-001: pin node #115 the type-22 apply delegate 0x609a740 and the serializer helper 0x60971c0

## Task and bounded question

Task RE-001 (Options / Configurable). Bounded question: what do the
type-22 apply delegate `0x609a740` and the serializer helper `0x60971c0`
do in node #115? This resolves the two open unknowns left by PR #4320
("0x609a740 internals", "0x60971c0 internals").

## Artifact

Node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(verified against `provenance/artifacts.json` by `gen_records.py` and
`verify.py`).

## What was pinned

### 0x609a740 — type-22 apply delegate (FDE 0x609a740..0x609b6f3)

Sole caller: `0x609b80f`, inside apply-created `0x609b700` (type == 22
arm). Reached from the arm `0x60bf212` (shipped in #4320) via the
no-'=' forwarder `0x609ba30` → create-by-name `0x609b8a0` → scan
`0x6096f40` → `0x609b700`.

Signature (traced through that chain):
`(Status* out, ConfigOptions* config, Configurable* object,
OptionTypeInfo* record, std::string* name, std::string* remaining_key,
std::string* value, options-base* out_slot)`.

- Field resolution: `target = options_base + record->offset (+0x00)`;
  when any of record flags `0x200/0x400/0x800` is set the field is
  dereferenced once (pointer/shared_ptr field), else the field address
  itself is the target. A null options-base yields a null target.
  Same gate as the arm and the serializer.
- The 0x50-byte ConfigOptions is copied to the stack (copy function
  `0x60b9d70`, shipped in #4320). On the record-flags-`0x100` branch
  the copy's `+0x04` byte is zeroed; on the clear branch `+0x04` is
  tested instead.
- Dispatch: if the remaining key equals the name, or equals `"id"`,
  the object vtable slot 10 (ConfigureOption core `0x60986b0`) is called
  with `(Status*, object, config-copy, record, remaining_key, value)`.
  If the name ends with `".id"`, the value must equal the target's
  GetId() (slot 15, `0x5d32a30`); a mismatch builds Status code 4
  (kInvalidArgument) with prefix `"Option not changeable: "` (literal
  `0x4341c2`) at sites `0x609ae22` / `0x609b217`. On a match it
  configures via helpers `0x609a410` / `0x6097150`.
- Otherwise: GetId is written into the value string, `"."` is appended,
  and the remaining key is compared against `"<id>."` with
  `string_compare` (`0x61d13e0`); equal → slot 10; not equal → the value
  is split on `'='`: found → setter `0x6099e70`, not found → forwarder
  `0x609ba30`. An empty value on the terminal path stores Status code 0
  (kOk) at `0x609aacf`.

### 0x60971c0 — serializer helper (FDE 0x60971c0..0x609755b)

Signature `(std::string* out, Configurable* object, ConfigOptions*
config, std::string* empty)`; only `out` and `object` are used.
It calls the object's vtable slot 12 (`0x609de80`, shared) into a
temp string, then:

- empty result → moved into `*out` verbatim;
- result with no `'='` → moved into `*out` verbatim;
- result containing `'='` → `*out = "{" + result + "}"`
  (literals `0x44ecd8` = `{`, `0x432097` = `}`).

Eight direct callers (see `callers.tsv`), including the two serializer
call sites `0x60bbabc` / `0x60bbd2d` (shipped in #4320).

### 0x609de80 — vtable slot 12, shared nested serializer (FDE 0x609de80..0x609e29e)

Signature `(std::string* out, Configurable* object, ConfigOptions*
config, std::string* rcx_arg)`. Clears `out`, calls slot 15 (GetId)
into a temp string, then:

- if `ConfigOptions+0x28 != 1` AND the id is non-empty, calls
  `0x60985e0` for the nested options;
- if that nested output is non-empty, emits
  `[rcx-arg] + "id" + "=" + id + [ConfigOptions+0x08 string] + [nested]`;
- otherwise `out = id` (bare, possibly empty).

So the `id=…` prefix only appears when the nested options exist.

### Vtable convention (observed, not assumed)

Configurable vtable callees take `(out/status, object, …)` with the
object in RSI, not RDI. Verified in GetId `0x5d32a30`: it loads the
vtable from `(%rsi)`, calls slot 14 (Name) with `rdi = rsi` (object),
and writes the name into `*rdi` (string). The same convention holds
for slots 10, 12, 13, 15. Why the object is second is not established
— recorded as an open unknown.

### Vtables reconstructed

From `R_X86_64_RELATIVE` relocations (`.data.rel.ro` file bytes read 0
pre-relocation; the addend lives in the relocation entry). BBT vtable
at `0x64d39b8` (22 slots) and the second Configurable vtable at
`0x64cdad0` (21 slots; slots 0/1 have no RELATIVE reloc). Both share
slot 12 = `0x609de80` and slot 15 = GetId `0x5d32a30`. See `vtables.tsv`.

## Model and tests

`tools/type22_delegates_115.py` models the field-resolution gate, the
flags-`0x100` / `ConfigOptions+0x04` dispatch, the `".id"` ends-with
check, the `"<id>."` prefix compare, the `{…}` wrap rule, the slot-12
emission, and the two Status constructions.
`tests/test_type22_delegates_115.py` covers them (19 tests, passing).

## Files

- `records.json` — semantic records only (no per-instruction mnemonic list)
- `fn-*.objdump.txt` — whole-function verbatim excerpts (7 functions)
- `callers.tsv` — direct-call census (40 sites, byte scan of .text)
- `bss-string-lea.tsv` — 10 lea sites of the .bss string `0x6508980`
- `vtables.tsv` — the two Configurable vtable maps (43 slots)
- `literals.tsv`, `frames.txt`
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py`
  (re-run `python3 verify.py` — it prints ALL CHECKS PASSED)

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. All claims are
from static disassembly of the retained node #115 binary plus
`readelf` relocations/frames. The REA server / `make verify` /
`make catalogue-check` were not run here (packet-only change; the
packet's own `verify.py` plus the model tests are the verification).

## Open unknowns (kept separate)

- `0x609a410` internals (id-configure helper; 3 callers incl. `0x609b190`)
- `0x6097150` / `0x6097110` internals beyond the thin wrapper (slot-9 entry)
- `0x60985e0` internals (slot-12 nested-options emitter)
- `ConfigOptions+0x00/+0x04/+0x08/+0x28` C++ names and defaults
- `.bss` string at `0x6508980` identity (serializer null-object string;
  10 lea sites enumerated)
- `record+0xb8` name-string inference (from #4320)
- why the vtable callees take `(out, object)` with the object in RSI
- type-21/22 entries in maps beyond DBOptions/CFOptions (from #4320)
