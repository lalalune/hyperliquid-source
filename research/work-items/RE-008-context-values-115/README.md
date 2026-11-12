# RE-008: node #115 Context value decoders for tx_index, round, time, prev_time and system_nonce (135th stage)

- Component ID: abci. Question: open PR #6663 and the merged packet `RE-009-abci-binary-context-115` show that the struct Context decoder `0x30d1c60` calls `0x451c540` for `tx_index`, `0x4524ae0` for `round`, `0x3d4f3c0` for `time` and `prev_time`, and `0x421db60` for `system_nonce`. RE-009 says "exact source-level option types remain unresolved". What do these 4 functions decode?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6663. It does not depend on its files.
- Claim status: instruction bytes, branch and call targets, RIP-relative references, relocations, function extents from `.eh_frame_hdr`, and strings are observations. "newtype", "option", "None" and "Some" are inferred labels. The binary was not executed.
- Scope included: the 5 Context call sites, the 3 name stubs, the `_ExtStruct` name check, slot call, tag test and result stores of the 4 newtype readers, and the nil, read and store paths of the `tx_index` reader. Scope excluded: the `_ExtStruct` (MessagePack extension) paths, the bodies of the 3 slot readers, the `hardfork` decoder `0x32b03e0`, and the error values. No gate changes.

## Result

| Field | Decoder | What it is | Value read | Result on tag 9 |
|---|---|---|---|---|
| `round` | stub `0x4524ae0` | name `Round` (5, at `0x7d3b21`) → newtype reader `0x2f4f140` | slot `0x64e2580` → `0x348e980` | qword at +8 |
| `system_nonce` | stub `0x421db60` | name `SystemNonce` (11, at `0x7c9469`) → newtype reader `0x2f43af0` | slot `0x64e2580` → `0x348e980` | qword at +8 |
| `time`, `prev_time` | stub `0x3d4f3c0` | name `Time` (4, at `0x459f78`) → newtype reader `0x2f6ca60` → `0x2f6fa30` (same name, length 4) | slot `0x64dfec0` → `0x14b93c0` | 12 bytes at +4..+0xf, copied by both readers |
| `tx_index` | `0x451c540` | no name; marker `0xc0` (nil) is tested first | nil: no read; other markers: slot `0x64dfeb0` → `0x14b7aa0` | nil: 0 at +8; other: 1 at +8, value at +0x10 |

- Each stub is 3 instructions (extent `0x20`): `lea rdx,<name>`, `mov ecx,<length>`, `jmp <reader>`.
- Each of the 4 newtype readers starts with the same 34-byte check: name length 10 and the two immediates `_ExtStru` / `ct`. Only the name `_ExtStruct` takes the extension path. `Round`, `SystemNonce` and `Time` do not, so they reach the plain value read.
- Each newtype reader has exactly one call through its slot in its unwind extent.
- `round` and `system_nonce` use the same integer reader as the Context integer keys (`hardfork_height`, `height`, `next_oid`, `next_lid`, `next_twap_id`; see #6663).
- `time` and `prev_time` use the same reader slot `0x64dfec0` → `0x14b93c0` as the user-value field `l` in open PR #6603 (`Time` newtype, expected text `a formatted date and time string`). The type of the 12 bytes is not checked here.
- `tx_index` is an option (inference): nil is None (discriminant 0, no read), any other marker is Some (discriminant 1, u64 from the same reader as Context `mac`). This is the `tx_index` "sentinel" that RE-009 notes in the completion code.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/context_values_115.py --check
python3 -m unittest discover -s tests -p test_context_values_115.py
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The 9 `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool checks 5 Context call targets, 3 stubs (name lea, string, length, jump), 4 `_ExtStruct` checks, 4 slot calls with a scan that each reader extent has exactly one call through its slot, 3 slot relocations, 4 tag-9 tests, 10 result stores, 9 fixed byte runs in the `tx_index` reader with its 2 short branches, and 8 unwind extents. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoders on sample input (not allowed for this repository).

## Results and limitations

- Result: `round` is newtype `Round` and `system_nonce` is newtype `SystemNonce`, both around the Context integer reader; `time` and `prev_time` are newtype `Time` around the 12-byte reader `0x14b93c0`; `tx_index` is an option of u64 where nil is None.
- Limits: the extension (`_ExtStruct`) paths, the integer widths of the 3 slot readers, the meaning of the 12 `Time` bytes, and the `hardfork` decoder `0x32b03e0` are not checked.
