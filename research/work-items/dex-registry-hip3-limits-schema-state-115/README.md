# dex-registry: Hip3 limits, schema and state record serializers in node #115

This packet makes the three records inside the node #115 `Hip3` per-DEX state reconstructible as pure functions: `limits` (6 fields), `schema` (7 fields) and `state` (5 fields). For each record it fixes the field names and order, the value offset each field reads, which keys are inline and which go through the str writer, the two different key gates (`flag == 1` versus `flag != 0`), the option and enum dispatch, and every error exit. The reconstruction is proved against the original machine code of all three copy families (9 bodies) in 5,943 cases with 0 mismatches, and all 14 deliberately wrong reconstructions are caught.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry; first task: recover identifiers, lookup rules and deployment ownership checks).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No #94 material and no reference source were used.
- Claim status:
  - Observation: the bytes, call targets, key literals, jump tables and interpreted behaviour.
  - Inference: the serde/rmp reading of the code and the domain meaning of the field names.
  - Unresolved: the internals of the stubbed helpers.
- Scope:
  - Included:
    - `limits` serializers `0x2bc1190`, `0x449e700` and `0x549be00`.
    - `schema` serializers `0x2bc17c0`, `0x449ef90` and `0x549c580`.
    - `state` serializers `0x2bc0900`, `0x449dbc0` and `0x549b950`.
    - Their key literals, the three `disabled_state` jump tables, and the GOT slot `0x64e4d08` used for address rendering.
  - Excluded:
    - The internals of the u64, str, newtype, option, sub-record and grow callees. They are stubbed and listed in `callee-roles.tsv`.
    - The deserializer side.
    - Any progress gate.

These are the `limits`/`schema`/`state` helpers that the `Main`/`Hip3` enum serializers call: `0x2bc2700` calls `0x2bc1190`, `0x2bc17c0` and `0x2bc0900`, and the other two copy families call their counterparts.

## Reproduce

From the repository root, with Python 3 standard library only (binutils are not needed on PATH):

```sh
python3 tools/hip3_limits_schema_codec_115.py --out research/work-items/dex-registry-hip3-limits-schema-state-115
python3 -m unittest tests.test_hip3_limits_schema_codec_115
```

How the tool works:
- It checks the capture SHA-256 first and refuses any other input.
- It reads section headers through `tools/elf_index.py`, excluding NOBITS sections, and function extents through `tools/fde_extents.py`.
- It decodes each body with a fixed-pattern decoder for a closed x86-64 subset and interprets the original bytes. The capture is never executed and no external program is called.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output. The output contains no time, randomness or absolute path.

## Evidence

Coordinates are linked virtual addresses. Extents are FDE `[start, end)` values from `.eh_frame`. Every decoded byte count equals the FDE byte count (`functions.tsv`).

| Record | Entries | FDE bytes | Decoded instructions | Header byte |
|---|---|---|---|---|
| limits | `0x2bc1190`, `0x449e700`, `0x549be00` | 910, 910, 926 | 227, 227, 229 | `((flag ^ 1) << 4) \| 0x86` |
| schema | `0x2bc17c0`, `0x449ef90`, `0x549c580` | 1045, 1045, 1046 | 260, 260, 257 | `((flag ^ 1) << 4) \| 0x87` |
| state | `0x2bc0900`, `0x449dbc0`, `0x549b950` | 1062, 1049, 1062 | 258, 253, 258 | `((flag ^ 1) << 4) \| 0x85` |

`flag` is the struct-as-map byte at writer `+0x1b`. Flag 1 gives a fixmap (`0x86`), flag 0 a fixarray (`0x96`), and other values give other bytes, for example `0xb6` for flag 2.

The evidence files are:
- `functions.tsv`: extents, digests and call-site counts.
- `instructions.tsv`: all 2,229 decoded instructions.
- `callee-roles.tsv`: the role of each callee and its call-site count. The tool rejects any body whose call-target set differs from the role table.
- `literals.tsv`: inline ASCII immediates and rodata 16-byte loads.
- `field-keys.tsv`: each key, its length, its mode and when it is written.
- `jump-tables.tsv`: the `disabled_state` tables, read from the bytes (base, signed offsets, targets inside the body).
- `cases.tsv`, `paths.tsv`, `negative-controls.tsv` and `summary.json`.

Observed field tables. All three copies agree, except where noted.

**limits** (6 fields):
1. `total_oi_cap2`: value word +0x8, u64.
2. `oi_sz_cap_per_perp`: +0x10, u64.
3. `max_transfer_ntl2`: +0x18, u64.
4. `max_under_initial_margin_transfer_ntl2`: +0x20, u64.
5. `daily_px_range`: +0x0, u64.
6. `max_n_users_with_positions`: +0x28, through an outlined field helper.

Keys 1 to 3 are inline fixstr stores, written when `flag == 1`. Keys 4 and 5 go through the str writer, also when `flag == 1`. For field 6, copy `0x549be00` passes the key text to its helper. Copies `0x2bc1190` and `0x449e700` call a helper that writes the key itself: the 26-byte inline store at `0x2cea920` is gated on `flag != 0`, which is a human-read observation and is not part of the claim.

**schema** (7 fields):
1. `name`: str, words +0x8/+0x10.
2. `full_name`: str, words +0x20/+0x28.
3. `deployer`: the 20 bytes at +0x70.
   - Copies `0x2bc17c0` and `0x449ef90` render them with the GOT-slot callee `0x64e4d08`, which resolves through `R_X86_64_RELATIVE` to `0x2eabb50`. It is called with `(buf, 42, src, 20, 0)`, and the rendered text then goes to the str writer.
   - Copy `0x549c580` calls a newtype helper with the name `Address` (7 bytes) instead.
4. `oracle_updater`: optional address, tag byte +0x84, payload +0x85.
5. `fee_recipient`: optional address, tag byte +0x99, payload +0x9a.
6. +0x30: an outlined sub-record helper.
7. +0x50: an outlined sub-record helper.

The keys of fields 1 to 3 are inline (`flag == 1`). The keys of fields 4 and 5 go through the str writer when **`flag != 0`**. Only a tag byte equal to 1 selects the Some arm; tag bytes 0 and 2 both take the None arm.

**state** (5 fields):
1. `last_settlement_time`: a `Time` newtype at +0x8.
2. `deploy_time`: `Time` at +0x14.
3. `n_reserve_deployments_used`: u64 word +0x0.
4. `disabled_state`: the unit enum byte +0x20, dispatched through a 4-entry jump table to the variant names `Na`, `UserDisabled`, `ValidatorDisabled` and `m`.
5. `m`: the byte at +0x21, passed by value.

The first three keys are inline. The `disabled_state` key is written when `flag != 0`; the `m` key when `flag == 1`. Copy `0x449dbc0` passes the `Time` fields through a stack local that holds the field pointer, while the other copies pass `(name "Time", len 4, pointer)`. No bounds check precedes the jump-table load.

Error exits (all bodies):
- A failing str writer (`rax != 2`) yields `(0x8000000000000000, rax, rdx)`.
- A failing u64 writer (`out[0] != 2`) yields `(0x8000000000000000, out[0], out[1])`.
- A failing newtype, option or sub-record helper (`out[0] != 0x8000000000000004`) has its three words copied.
- Success stores `0x8000000000000004` in `out[0]` only.
- Every inline store is preceded by a reserve check: a single byte grows when `cap == len`, and an n-byte store grows when `cap - len < n`, through `(writer, len, n, 1, 1)`.

Human-readable excerpt (objdump, not used by the tool):

```
2bc0ac6: mov eax,ebp ; lea rcx,[rip+...] # 60923c
2bc0acf: movsxd rax,DWORD PTR [rcx+rax*4] ; add rax,rcx ; jmp rax
2bc1955: cmp BYTE PTR [r15+0x1b],0x0 ; je ...   # oracle_updater key gate
```

Ownership check:
- None of the nine entries occurs under `research/work-items` at the source commit, or in the file lists of open or our pull requests (`open.json`, `ours.json`).
- Our earlier draft `dex-registry-main-hip3-state-codec-115` stubbed these nine bodies. This packet is its stated next question and does not re-cover the enum serializers.

## Implementation and comparison

There is no Rust implementation yet. The implementation is a pure-Python reconstruction: `recon_serialize`, driven by the declarative tables `LIMITS_FIELDS`, `SCHEMA_FIELDS`, `STATE_FIELDS` and `DISABLED_STATE`. The original bytes run in a subset interpreter, and the two results are compared case by case: appended bytes, ordered call log (helper role, key text, value word or pointer), grow calls, final length and the three result words.

- **Capacity sweep:** for flag 1, 48 capacities with 0 to 47 bytes of slack, which crosses every inline reserve bound. For flags 0, 2 and 255, two capacities each.
- **Tag bytes:** schema options (0, 1, 2)²; state enum 0 to 3 × byte (0, 1, 255).
- **Failure injection:** every counted helper call is made to fail in turn, under every flag and tag combination.
- **Negative controls:** 14 wrong reconstructions, all caught (`negative-controls.tsv`):
  - keyed gates swapped (`eq1` ↔ `ne0`);
  - header without the flag;
  - field count off by one;
  - Some for any non-zero tag;
  - inclusive reserve;
  - fields swapped in each record;
  - u64 errors copied as three words;
  - success writing three words;
  - tail key not passed;
  - `disabled_state` names rotated;
  - `Time` passed directly in every copy.
- **Byte mutations in the tests:** the limits header `or` immediate, the `oracle_updater` gate immediate and a jump-table entry are each changed in a copy of the capture. Each change is detected against the reconstruction.

## Results and limitations

- Results (`summary.json`):
  - 5,943 of 5,943 cases match.
  - 81 distinct (body, outcome) paths are covered (`paths.tsv`).
  - All 14 negative controls are caught.
  - 12 jump-table entries are verified from bytes, and every interpreted indirect jump lands on the entry the enum byte selects.
- Limits:
  - Helper internals are stubs, so their wire encodings (u64 width, address text format, `Time` layout, sub-records at schema +0x30/+0x50) are not claimed.
  - The trailing `2` in three limits keys and the variant name `m` (which shares the rodata byte with the `m` key) are byte observations; their domain meaning is unresolved.
  - Flag bytes other than 0 and 1, tag byte 2 and enum bytes above 3 describe the compiled code, not states a valid Rust value reaches.
- No progress gate is requested.

Next question: what do the schema sub-record helpers at +0x30/+0x50 (`0x2ce96a0`, `0x2ce6f90` and their copies) emit, and which type does the `state` byte field `m` hold?
