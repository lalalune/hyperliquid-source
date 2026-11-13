# RE-008: node #115 ExchangeMisc field `i` is `Option<(u64, bool)>` (stage 92)

- Component ID: abci. Question: #6099 found that field `i` of `ExchangeMisc` (box `+0x39a8` u64, `+0x39b0` byte) decodes msgpack nil to byte 2, and that three simulate-panic sites arm on `byte & 1` while three arm on `byte == 0`. It left open what the byte is.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6091 and #6099; does not depend on their files.
- Claim status: instruction bytes, relocations, the jump-table arms and the string are observations. "Option", "tuple", "bool", "None" and "Some" are inferred labels from the decoder shape and the msgpack markers. The binary was not executed.
- Scope included: the decoder `0x47922c0` nil, fixarray and fallback paths; the element-1 decoder `0x586a170` and the bool decoder `0x3482410` arms for 0xc2/0xc3; the expecting text of the fallback visitor; the six panic-site tests. Scope excluded: the element-0 decoder body (`0x348e980`), the array16/array32 tuple path inside `0x3493900`, and what sets `i` in a real state file.

## Reproduce

```
python3 tools/field_i_stop_kind_115.py --check
python3 -m unittest tests.test_field_i_stop_kind_115
```

The tool reads the ELF only. The four `*.objdump.txt` files (GNU objdump 2.42) are for review; the tool does not read them.

## Evidence

- **None.** `0x47923bf cmp al,0xc0` → `0x47923c3 mov byte [rbx+0x10],2`.
- **Tuple of two.** On a fixarray, element 0 is decoded through slot `0x64e2580` (→ `0x348e980`, call `0x479298d`); element 1 through `0x586a170` (call `0x47929b2`), which calls slot `0x64e2590` (→ `0x3482410`). The tuple path treats a returned 2 as a missing element (`0x47929ce cmp al,2`) and keeps `and al,1` (`0x47929d6`), then stores the u64 and the byte (`0x4792a35`, `0x4792a3a`) with Ok tag 9.
- **Bool.** In `0x3482410`, jump table `0x78cfd8` sends marker 0xc2 to `0x3482435 xor eax,eax` and 0xc3 to `0x3482549 mov al,1`; both store the byte at `+1` and Ok tag 9 (`0x348254b`, `0x348254e`). These are msgpack `false` and `true`.
- **Other markers** go through slot `0x64e2598` (→ `0x3493900`); its type errors use the visitor vtable whose expecting entry `0x646be68` → `0x38db600` prints "a tuple of size 2" (`0x7a0390`, length 0x11).

## Result

`i` is `Option<(u64, bool)>` with None stored as byte 2. The six sites therefore split by the bool:

| Site | Function | Test | Arms on |
|---|---|---|---|
| begin A | `0x5483850` | `0x5483903` | `Some((h, true))` |
| begin B | `0x5483f50` | `0x5484003` | `Some((h, true))` |
| `0x2bdf270` | `0x2bdf270` | `0x2bdf30d` | `Some((h, true))` |
| quorum-entry builder B | `0x5486720` | `0x5488ed4` | `Some((h, false))` |
| quorum-entry builder A | `0x54897e0` | `0x548bfc9` | `Some((h, false))` |
| `0x2c71eb0` | `0x2c71eb0` | `0x2c7444e` | `Some((h, false))` |

A tuple has no field names, so the binary gives the bool no name. This answers the polarity question in #6091.

## Limits

- The element-0 decoder body and the non-fixarray tuple path are not mapped.
- What writes `i` in practice (state files, tests) is not traced.
- Labels for the bool's meaning (e.g. "panic in begin step" vs "panic in quorum builder") are inferences from the site split only.
