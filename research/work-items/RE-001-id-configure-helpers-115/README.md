# RE-001: pin node #115 the id-configure helper 0x609a410 and the slot-9 entry 0x6097150/0x6097110

## Question

How does a type-22 record's apply delegate decide the final option name
(the `id` handling), and how does the surviving option map then reach the
object through the Configurable vtable slot 9?

This packet resolves the open unknowns left by #4328 (the type-22 delegate
0x609a740, which calls both routines pinned here) and re-ships the two
#4320 excerpts this packet depends on (map parser 0x60c1190, setter
0x6099e70) byte-for-byte.

## Task

RE-001 (node #115 reconstruction). One bounded behavior: the id-configure
helper plus the slot-9 entry/tail and the shared slot-9 implementation,
with their map helpers.

## Findings

### 0x609a410 — id-configure helper

Signature: `(Status* out, const std::string* input, const std::string* id,
std::string* out_name, std::unordered_map<std::string, std::string>* map)`.
Returns Status* out; **always kOk**. Decision tree:

1. input empty → out_name = id.
2. input equals the .bss string at 0x6508980 (size then memcmp) → out_name = id.
3. input has no `=` → out_name = input.
4. input parses as a map (parser 0x60c1190), no `id` key, id non-empty →
   out_name = id, map entries survive for slot 9.
5. input parses, no `id` key, id empty → out_name = input, map cleared.
6. input parses with an `id` key → out_name = map["id"], the `id` entry is
   erased (0x609a2f0), other entries survive; if out_name equals the .bss
   string it is truncated to empty.
7. parse failure → out_name = input, map cleared, parse error discarded,
   out reset to kOk.

The `id` key is a 2-byte SSO string "id" (0x6469) built on the stack;
lookup is 0x609a1b0. Delegate call site 0x609b190 (in 0x609a740, #4328):
rdi = Status* at -0x140(%rbp), rsi = value string at -0x160(%rbp),
rdx = id string at -0x178(%rbp) (GetId output), rcx = empty SSO out-name
string at -0xd0(%rbp), r8 = empty unordered_map at -0x110(%rbp) (single
bucket, count 1, element_count 0, max_load 1.0f). Other callers: 0x609e5bf
and 0x609ea72, both in FDE 0x609e510..0x609f073 (sibling id-configure
caller). The delegate's post-call status check at 0x609b1b8 never fires
from this helper.

### 0x6097150 / 0x6097110 — configure slot-9 entry and tail

0x6097150 sets arg5 (r8) to 0 and tail-calls 0x6097110 with the same
(rdi, rsi, rdx, rcx); returns Status*. Five callers: 0x609b535 (delegate;
only when the map element_count != 0), 0x609e314, 0x60c3bac, 0x60c45ac,
0x60cf385. 0x6097110 loads the vtable from (%rsi) and calls slot 9
(offset 0x48) with the same args; returns Status*. Two callers: 0x609716f
(inside 0x6097150) and 0x609a032 (inside setter 0x6099e70, arg5 = 0).

### 0x609d0e0 — vtable slot 9 (shared)

Signature: `(Status* out, Configurable* object, ConfigOptions* config,
std::unordered_map<std::string, std::string>* map, int arg5)`. Slot 9 of
both Configurable vtables (BBT 0x64d39b8, second 0x64cdad0) — and of 66
vtable slots across the Configurable vtables (R_X86_64_RELATIVE count).
Two direct callers (0x607e447, 0x60a24a1) are thin wrappers that forward
their args unchanged.

- Map empty (element_count +0x18 == 0): if ConfigOptions+0x00 byte 3 != 0,
  call vtable slot 5 (offset 0x28; BBT 0x60db570, second 0x6095e70) with
  (Status*, object, ConfigOptions*); else return kOk.
- Map non-empty: copy the first 0x50 bytes of ConfigOptions to stack copy
  C1 at 0x50(%rsp); if ConfigOptions+0x00 byte 0 == 0, force C1.string =
  `"; "` (literal 0x4409b0, 2 chars, `_M_replace`) and call the delimiter
  pre-step 0x6098510; call 0x609c8c0 (Status*, C1, object, map, arg5); then
  if ConfigOptions+0x00 byte 3 != 0, re-copy ConfigOptions to C1, patch
  C1+0x00 low word to 0x0101 and C1+0x03 to 1, and call setter 0x6099e70
  (Status*, object, C1, S0, arg5); if byte 3 == 0, the setter fires only
  if out code != 0 and S0 is non-empty. S0 = empty SSO string at
  0x30(%rsp); its only writer in the call graph is 0x6097630 (via
  0x6098510), not decoded.

ConfigOptions is 0x50 bytes: +0x00 u32 flags, +0x04 u8, +0x08 std::string
(delimiter), +0x28 u32, +0x2c u8, +0x30 u64, +0x38 16 bytes, +0x48
shared_ptr.

### Map helpers

- 0x609a1b0 — unordered_map find: linear scan while element_count <= 20,
  hash path with seed 0xc70f6907 above; returns node* or null. Callers:
  0x609a5bf (in 0x609a410), 0x609c43f (in 0x609bcb0).
- 0x609a2f0 — erase: unlink, destroy both strings, operator delete 0x50
  bytes, decrement element_count, returns next node. Callers: 0x609a603
  (in 0x609a410), 0x609bef5 and 0x609c44f (in 0x609bcb0).
- 0x5d5b300 — clear/destroy: 98 direct call sites binary-wide; 6
  packet-relevant sites recorded (0x609a509, 0x609a661 in 0x609a410;
  0x609a087 in setter; 0x609b35d in delegate; 0x609cb05 in 0x609c8c0;
  0x609e9fe in 0x609e510).
- Map node layout: 0x50 bytes; next +0x00, key string +0x08/+0x10/+0x18,
  value string +0x28/+0x30/+0x38, hash +0x48. Map layout: 56 bytes;
  buckets +0x00, bucket_count +0x08, before_begin +0x10, element_count
  +0x18, max_load_factor +0x20 (float 1.0), next_resize +0x28,
  single_bucket +0x30.

### 0x6098510 — delimiter pre-step

Truncates S0 to empty, forwards (out, C1, object, fresh empty string, S0)
to 0x6097630. Five callers: 0x609d5ea (slot 9), 0x609e80f (in 0x609e510),
0x60b96cd, 0x60b977f, 0x60d4187.

### 0x609e2d0 — null-checked slot-9 entry

Null object + non-empty map → Status code 4 (kInvalidArgument) via
0x61cf670 with slices ("Cannot configure null object ", 29) + ("", 0);
null object + empty map → kOk; non-null → forward to 0x6097150 and move
the Status into out. Five callers: 0x5eba500, 0x5fd3866, 0x5fd3b56,
0x5fd4b76, 0x5feda73.

### 0x61cf670 — Status two-slice ctor

out->code = rsi byte, out+0x01 = rdx byte, out+0x02 = r9 byte, message =
slice1 + slice2 (heap copy, NUL-terminated); rcx = &slice1, r8 = &slice2.
Shared binary-wide (hundreds of call sites).

### 0x609c8c0 — map-copy-and-apply

Copies the map into a fresh bucket array (rehash via 0x6095b80), iterates
the 0x30-byte-element array at object+0x08..+0x10, calls 0x609bcb0 once
per element whose +0x28 pointer is non-null. Called once, from slot 9
(0x609d30a).

### 0x609bcb0 — per-entry apply

For each map entry, resolve the option name via vtable slot 13
(GetOptionName 0x609d980, call at 0x609be72), scan for the record via
0x60ba0b0 (call at 0x609be8a), apply via apply-created 0x609b700 (call at
0x609bec5; dispatches to the type-22 delegate 0x609a740 for type-22
records). Called once, from 0x609c8c0 (0x609ca6d). Inner branches not
decoded (open unknown).

### Call chain

arm 0x60bf212 (#4320) → forwarder 0x609ba30 → create-by-name 0x609b8a0 →
scan 0x6096f40 → apply-created 0x609b700 (type == 22) → delegate 0x609a740
(#4328) → 0x609a410 and, when the map survives, 0x6097150 → 0x6097110 →
slot 9 0x609d0e0 → 0x609c8c0 → 0x609bcb0 → apply-created 0x609b700 per
entry.

### .bss string 0x6508980

std::string in .bss, runtime-initialized, identity/content still open.
All 10 lea sites (0x6077907, 0x607e8e0, 0x6086c84, 0x609e567, 0x60a7534,
0x60bbc99, 0x60bf710, 0x60bf730, 0x61372c8, 0x61d2974) only read it (size
compare, memcmp, `_M_assign` from it); no writer found among them.

### Record layout (from #4320, cited)

OptionTypeInfo 0xd8 bytes; offset +0x00, parse_function std::function
+0x08 (manager +0x18, invoker +0x20), serialize_function +0x28, other
functions +0x48/+0x68/+0x88, type +0xa8, verification +0xac, flags +0xb0,
name string +0xb8 (inferred).

## Files

- `records.json` — semantic records only (functions, branches, callers,
  literals, layouts, open unknowns). No per-instruction mnemonic list.
- `fn-*.objdump.txt` — whole-function verbatim objdump excerpts (14).
- `export_excerpts.py` — the generator that produced the excerpts.
- `callers.tsv` — direct-call census (51 sites) for the pinned routines.
- `census.py` — the generator that produced callers.tsv.
- `slot9-vtables.tsv` — slot-9 target in both Configurable vtables.
- `map-clear-count.txt` — binary-wide count of 0x5d5b300 call sites (98).
- `literals.tsv` — pinned string literals with lengths.
- `frames.txt` — the 14 FDE ranges.
- `verify.py` — re-runs the excerpt/census/literal/FDE checks and the
  model tests. Run `python3 verify.py` from this directory.
- `gen_records.py` — the generator that produced records.json.

## Model

`tools/id_configure_helpers_115.py` models 0x609a410's seven outcomes,
the slot-9 branch structure (delimiter pre-step, setter fallback), the
null-checked entry, and the map find/erase/clear semantics.
`tests/test_id_configure_helpers_115.py` exercises them (25 tests).

## Verification

`python3 verify.py` — ALL CHECKS PASSED (artifact digest, manifest,
excerpts byte-identical to fresh objdump, FDE identities, literals,
caller census, slot-9 vtable rows, semantic-only records, model tests,
spot bytes). `python3 -m pytest -q tests/test_id_configure_helpers_115.py`
— 25 passed.

## Environment limits

No cargo/rustc, no git-lfs, no Ghidra/Java on this VM. All claims are
from static disassembly of the pinned node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
plus objdump/readelf; `make verify`, `make test`, and
`make catalogue-check` were not run (they need the REA server / toolchains
this VM lacks). The excerpts were regenerated from the binary and diffed
byte-for-byte by verify.py.

## Open unknowns

- 0x6097630 internals (the S0 writer behind the delimiter pre-step).
- 0x609c8c0 tail branches (0x609cb60..0x609d08e) and the C++ identity of
  the 0x30-byte-element array at object+0x08..+0x10.
- 0x609bcb0 inner branches (0x609bf50..0x609c782).
- Slot 5 C++ name; slot-9 arg5 C++ meaning.
- ConfigOptions+0x00/+0x04/+0x08/+0x28 C++ names and defaults.
- .bss string 0x6508980 identity/content.
- 0x609e510 host identity.
- Record+0xb8 name-string inference.

## Do not pick

This packet pins 0x609a410, 0x6097150, 0x6097110, 0x609d0e0, 0x609a1b0,
0x609a2f0, 0x5d5b300, 0x6098510, 0x609e2d0, 0x609c8c0, 0x609bcb0, 0x61cf670,
0x60c1190, 0x6099e70 — do not re-pin them. (Also #4328's 0x609a740,
0x60971c0, 0x609de80, 0x5d32a30, 0x60986b0, 0x61d1390, 0x61d13e0 and #4320's
0x60bedc0, 0x60bb9a0, 0x60bf1e0, 0x609b700, 0x609ba30, 0x609b8a0, 0x6096f40.)
