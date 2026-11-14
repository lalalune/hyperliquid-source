# RE-008: node #115 callers of the 0x-prefixed hex encoder (fifty-first stage)

- Component ID: abci. Question: the fiftieth stage (open PR #6030) found that abci hash-tree leaves are written as `d9 42 "0x"` plus 64 lowercase hex digits by the encoder `0x2eabb50`, reached through slot `0x64e4d08`. Where else does the node use that encoder, and with which shapes?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6029 and #6030. The tool imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, relocations, the hex table bytes, call and load censuses, immediate operands and FDE extents are observations. "Address", "hash", "u128" and "quantity" are inferred labels from the byte lengths and the trim flag. The binary was not executed.
- Scope included: the head of the encoder; every `call [rip+disp]` to the slot; the immediate arguments in the 24 bytes before each call; the enclosing FDE of each site; string loads in the enclosing functions that start with a small set of tags. Scope excluded: the 39 RIP-relative loads of the slot (listed, not classified), what each caller encodes, and the callers' callers. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hex_digest_callers_115.py --check
python3 -m unittest tests.test_hex_digest_callers_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only.

## Evidence 1: the encoder

- Slot `0x64e4d08` is relocated to `0x2eabb50`. No `call rel32` targets `0x2eabb50`.
- Arguments: `rdi` output, `rsi` output capacity, `rdx` input bytes, `rcx` input length, `r8b` trim flag.
- `lea rax, [rcx*2+1]; cmp rsi, rax; jbe` (`0x2eabb51`): the capacity must exceed `2*len + 1`.
- `mov word [rdi], 0x7830` (`0x2eabb62`): the output always starts with `0x`.
- `shr r10d, 4; sete r11b; test r8b, r11b; jne` (`0x2eabb77..0x2eabb87`): with the trim flag set, the first byte's high digit is skipped when it is 0.
- Digits come from `0x455d40` = `0123456789abcdef`.

## Evidence 2: call census

629 `call [rip+disp]` sites reach the slot. At 609 of them the 24 bytes before the call contain `mov esi, imm32; mov ecx, imm32` and end with `xor r8d, r8d`:

| Input bytes | Capacity (`esi`) | Output | Trim | Sites | Functions | Functions loading tag strings |
|---|---|---|---|---|---|---|
| 20 | 0x2a | `0x` + 40 digits | 0 | 440 | 388 | `user` 33, `evm` 9, `address` 3 |
| 32 | 0x42 | `0x` + 64 digits | 0 | 123 | 105 | `abci` 3 |
| 16 | 0x22 | `0x` + 32 digits | 0 | 46 | 43 | none |

- Every fixed shape has capacity `2*len + 2`, exactly enough for the prefix and the digits.
- The two hash-tree leaf sites of the fiftieth stage (`0x41c5203`, `0x41c794d`) are in the 32-byte shape.
- Inference: 20 bytes are addresses, 32 bytes are hashes and digests, 16 bytes are 128-bit values.

The other 20 sites take the length from a register. 9 pass trim 0, 8 pass trim 1, and 3 set `r8d` before the last instruction. They sit in short functions (`0x2630fd0`, `0x26310e0`, `0x4e1c070` and others in `evidence.json`) that pass the caller's slice through. Inference: the trim-1 sites encode variable-length quantities.

## Implementation and comparison

The tool pins 12 instruction byte runs, the slot relocation and the hex table, then recomputes the censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). An objdump-based scan of the same sites gave the same three shapes and 20 others.

## Results and limitations

- Result: the abci digest leaf uses the same untrimmed `0x` form as 122 other 32-byte sites; 20-byte values are the most common use.
- Limits: the shape test is a byte pattern; a site whose immediates sit more than 24 bytes before the call counts as "other". The tag-string count only looks at strings loaded with `lea [rip+disp]` that start with the tag. The 39 slot loads, what each site encodes, and which component each function belongs to are not mapped.
- Next lead: the 39 RIP-relative loads of the slot (indirect calls through a register).
