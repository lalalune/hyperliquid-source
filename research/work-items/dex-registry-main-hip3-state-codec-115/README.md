# dex-registry: Main/Hip3 per-DEX state codec in node #115

This packet makes the node #115 `Main`/`Hip3` per-DEX state enum reconstructible in both directions. The writer side is rebuilt as a pure function: tag selection by the niche word, the struct-as-map flag, every inline key, the Hip3 optional-field count, helper call order, capacity reserves and every error exit. The reader side is the exact-name variant visitor. Both are proved against the original machine code of all three serializer copies and all three visitor copies, in 11,388 cases with 0 mismatches.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No #94 material and no reference source were used.
- Claim status: observation for the bytes, call targets, key literals and interpreted behaviour; inference for the serde/rmp names and the meaning of the payload fields; unresolved for the internals of the stubbed field helpers.
- Scope included and excluded:
  - Included:
    - Serializers `0x2bc2700`, `0x44f6f40` and `0x549d760`.
    - Visitors `0x2b94d80`, `0x4440220` and `0x5469f10`.
    - Variant-name pools `0x644cbb0`, `0x648a408` and `0x64a9c20`.
    - The key literals those bodies reference.
  - Excluded:
    - The internals of the field, header, key, drop and grow callees. They are stubbed and listed in `callee-roles.tsv`.
    - Callers of the serializers.
    - The deserializer side of the payload structs.
    - Any progress gate.

## Reproduce

From the repository root, with Python 3 standard library only (no binutils on PATH is required):

```sh
python3 tools/dex_kind_state_codec_115.py --out research/work-items/dex-registry-main-hip3-state-codec-115
python3 -m unittest tests.test_dex_kind_state_codec_115
```

How the tool works:
- It first checks the capture SHA-256 and refuses any other input.
- It reads section headers through `tools/elf_index.py`, excluding NOBITS sections, and function extents through `tools/fde_extents.py`.
- It decodes each body with a fixed-pattern decoder for a closed x86-64 subset and interprets the original bytes. The capture is never executed and no external program is called.
- Running it twice, with different `PYTHONHASHSEED` and `TZ`, gives byte-identical output. The output contains no time, randomness or absolute path.

## Evidence

Coordinates are linked virtual addresses. Extents are FDE `[start, end)` values from `.eh_frame`.

| Role | Entries | FDE bytes | Decoded instructions |
|---|---|---|---|
| serializer, (out, value, writer) | `0x2bc2700`, `0x549d760` | 1844 each | 428 each |
| serializer, (out, writer, value), writes own key `moh` | `0x44f6f40` | 1914 | 455 |
| exact-name visitor | `0x2b94d80`, `0x4440220`, `0x5469f10` | 67 each | 20 each |

The evidence files are:
- `functions.tsv`: body digests and callee sets.
- `instructions.tsv`: all 1,371 decoded instructions.
- `callee-roles.tsv`: the role of every callee and every call site.
- `serializer-literals.tsv`: every key reference, inline store and flag compare.
- `visitor-literals.tsv`: length gate, name immediates, result stores, variant count and pool.
- `variant-pool.tsv`: pool slots resolved through `R_X86_64_RELATIVE` entries of `.rela.dyn`.

Observed serializer behaviour (all three copies):

1. **Tag.** The first word of the value selects the arm. `0x8000000000000000` selects `Main`; any other word selects `Hip3`. This holds even for `0x8000000000000001` and `0xffffffffffffffff`.
2. **Envelope.** The output is a msgpack fixmap of one entry, `0x81`, followed by the fixstr name (`0xa4 Main` or `0xa4 Hip3`). Every inline store is preceded by a reserve check. A single byte grows when `cap == len`; an n-byte store grows when `cap - len < n`. The grow callee is called with `(writer, len, n, 1, 1)`.
3. **Struct-as-map flag.** The flag is the byte at writer `+0x1b`.
   - Main writes its header byte as `((flag ^ 1) << 4) | 0x84`. That gives `0x94` (fixarray 4) for flag 0, `0x84` (fixmap 4) for flag 1, and `0xb4` for flag 2.
   - Hip3 calls the map-header callee when `flag != 0` and the array-header callee when `flag == 0`.
   - Inline keys are written only when `flag == 1`. The `moh` prefix key of `0x44f6f40` is written when `flag != 0`.
   - So a flag byte of 2 produces a mixed encoding: a map header with no inline keys.
4. **Main fields in order.**
   - `asset_to_recent_oi` (value+0x8) and `override_max_oi_per_second` (value+0x28), both through keyed helpers.
   - The 28-byte key `reset_recent_oi_bucket_guard`, written inline as `0xbc` plus two overlapping 16-byte rodata loads, followed by a value helper on value+0x48.
   - The key `assets_at_open_interest_cap`, through the key writer (success is `rax == 2`), followed by a value helper on value+0x58.
5. **Hip3 fields.**
   - Header count = `3 + [value+0x30 != 0] + [value+0x90 != 0x8000000000000001] + [value+0x78 != 0]`. It is computed with `setne` and two `sbb` instructions.
   - Then `limits` (value+0xf8), `schema` (the pointer loaded from value+0x128) and `state` (value+0xd0).
   - Then the optional `hip3_backstop_liquidator_state`, gated on value+0x30 but serializing value+0x0.
   - Then the optional `ss` (value+0x90) and `df`. `df` is gated on value+0x78 but serializes value+0x48.
   - Copies `0x2bc2700` and `0x549d760` call a drop callee on a temporary holding `0x8000000000000001`: once before the envelope and once after the backstop field. `0x44f6f40` has no such call.
6. **Errors.**
   - A keyed or value helper that does not return `0x8000000000000004` has its three result words copied to `out`, and the serializer stops.
   - A failing key writer yields `(0x8000000000000000, rax, rdx)`.
   - A failing header yields `(0x8000000000000000, hdr[0], hdr[1])`.
   - Success stores `0x8000000000000004` in `out[0]` only.

Observed visitor behaviour: a length gate of 4, then a dword compare against `Main` and then `Hip3`. A match stores the word `0x0009` or `0x0109` and returns `out`. Anything else calls the unknown-variant callee with `(out, ptr, len, pool, 2)`; each pool holds `Main`, `Hip3` in tag order.

Human-readable excerpt (objdump, not used by the tool):

```
2b94d80: cmp $0x4,%rdx ; jne err
2b94d86: cmpl $0x6e69614d,(%rsi) ; je main
2b94d8e: cmpl $0x33706948,(%rsi) ; jne err
2b94d96: movw $0x109,(%rdi)
```

Ownership check: none of the six entries, three pools or seven key strings occurs under `research/work-items` at the source commit. None of them occurs in the file lists of open pull requests either. Open #3310 (RE-007 open-interest cap requests) covers different functions.

## Implementation and comparison

There is no Rust implementation yet. The implementation is a pure-Python reconstruction (`recon_serialize`, `recon_visitor` in the tool). The original bytes run in a subset interpreter, and the two results are compared case by case:

- **Serializer capacity sweep** (`serializer-cases.tsv`, 4,536 cases): 3 copies × 3 flag bytes (0, 1, 2) × 12 values × 42 capacity/length settings. The values are Main, eight Hip3 option combinations, and three Hip3 head words around the niche. Each case compares the appended bytes, the ordered call log (helper role, key text and value offset, header count, grow `len+n`), the final length and the three result words.
- **Failure injection** (`failure-cases.tsv`, 624 cases): every counted helper call is made to fail in turn, for every copy, flag and value.
- **Visitors** (`visitor-cases.tsv`, 2,076 inputs × 3 copies = 6,228 cases): every single-byte substitution with all 256 values, all prefixes, padding, case changes and splices.
- **Negative controls** (`negative-controls.tsv`): 13 deliberately wrong reconstructions run through the same comparison, and every one is caught. Among them:
  - the header is always a map;
  - keys are written for any nonzero flag;
  - the count ignores the options, or ignores only `ss`;
  - the Main fields are swapped;
  - the Main header is always a map;
  - every head `>= 0x8000000000000000` is treated as Main;
  - the drops are omitted;
  - the reserve check is inclusive;
  - names match by prefix, by case fold, swapped, or by the first three bytes.
- `paths.tsv` lists the 279 distinct (function, step count, outcome) paths taken.

## Results and limitations

- Results (`summary.json`):
  - Serializer: 5,160 of 5,160 cases match.
  - Visitor: 6,228 of 6,228 cases match.
  - All 13 negative controls are caught.
  - The unit tests also change single bytes of the original: the `Hip3` immediate, the header `or` immediate and a reserve bound. Each change is detected.
- Limits:
  - The field, header, key-writer, drop and grow callees are stubs, so their encodings are not claimed. The call log records only which helper runs, on which value offset and with which key.
  - The roles of the 14 callees per copy are fixed in the tool and checked against each body's exact call-target set.
  - The domain names (Main DEX versus HIP-3 DEX, open-interest bucket fields) come from the literal key text. What `ss`, `df` and `moh` stand for is unresolved.
  - Flag bytes other than 0 and 1, and head words that a valid Rust value never holds, describe the compiled code, not reachable states.
- No progress gate is requested.

Next question: which callers pass a writer and a value to `0x44f6f40` under the `moh` key, and what do the stubbed `limits`/`schema`/`state` helpers (`0x2bc1190`, `0x2bc17c0`, `0x2bc0900`) emit?
