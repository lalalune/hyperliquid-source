# RE-008: node #115 Locus cls element +0x58 is Clearinghouse.meta.collateralToken (stage 103)

- Component ID: abci. Question: stage 102 (open PR #6216) found that 14 paired move_token call sites test the word at Locus `cls` element `+0x58` (0x510-byte elements at box `+0x7c8`, #6207) and send a clearinghouse's tokens to clearinghouse 0 when it is 0, else to spot. This packet names that word.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6207 and #6216; does not depend on their files.
- Claim status: instruction bytes, offsets, string bytes and RIP-relative targets are observations. "Clearinghouse", "PerpMeta" and the field names come from the binary's own serde strings. "Token 0 is USDC" and the move_token reading of #6216 are inferences. The binary was not executed.

## Reproduce

```
python3 tools/clearinghouse_field_58_115.py --check
python3 -m unittest tests.test_clearinghouse_field_58_115
```

The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: Clearinghouse field matcher

`0x445dd80` switches on name length minus 3 through table `0x7ce8b0` (`add rdx,-3`; `cmp rdx,0x26`). Pinned arms: `moh` → 17, `lnsgt` → 13, `halted_assets` → 9, `usdc_ntl_scale` → 14 (each `mov cl,imm` after an immediate compare of the name bytes). This is `struct Clearinghouse with 19 elements`.

## Evidence 2: Clearinghouse layout (JSON serializer `0x4482170`)

| Field name (string) | Value operand |
|---|---|
| `meta` (`0x459ef4`, len 4) | `rbx` (+0x0) via the nested serializer |
| `user_states` (`0x7d07c9`) | `lea rdi,[rbx+0x60]` |
| `oracle` (`0x7d19dd`) | `lea rdi,[rbx+0x148]` |
| `total_net_deposit` (`0x7d19e3`) | `mov rsi,[rbx+0x4a8]` |

`+0x4a8` is the balance that stage 100's move_token leg debits and credits.

## Evidence 3: PerpMeta layout (`meta`, serializer `0x3c40400`)

| Field | Offset |
|---|---|
| `universe` | +0x0 (`mov rcx,rbx`) |
| `collateralTokenName` | +0x18 (`add rbx,0x18`) |
| `marginTableIdToMarginTable` | +0x30 |
| `pdi` | +0x50 (`mov rsi,[rbx+0x50]`) — the index #6207 checks against q |
| `collateralToken` | +0x58 (`lea rcx,[rbx+0x58]`, name length 15) |

## Evidence 4: deserialisers write the same offset

- PerpMeta seq visitor `0x2f88180`: `mov [r14+0x50],rax` (`pdi`) and `mov [r14+0x58],r12` at `0x2f884ab`, where `r12` is the decoded element 3 (`invalid_length(3)` at `0x2f88574`; `collateralToken` is the fourth PerpMeta field).
- PerpMeta map visitor `0x30e94a0`: `mov [rbx+0x58],rax` at `0x30eaddb`.

## Result

Locus `cls` element `+0x58` = `Clearinghouse.meta.collateralToken`. Combined with #6216: the 14 paired call sites move a clearinghouse's tokens to clearinghouse 0 when its collateral token is 0, and to spot otherwise (inference: token 0 is the USDC base token).

## Limits

- Writers other than the two deserialisers were not found by a bounded search; a disp8 `+0x58` census over the 267 functions that load the cls unwrap record (159 stores, 246 loads, 22 compares) is not specific to cls elements and is not claimed.
- Readers other than the #6216 P sites are not enumerated.
- The other 15 Clearinghouse field indices and the type of `collateralToken` (u32 or u64) are not pinned.
