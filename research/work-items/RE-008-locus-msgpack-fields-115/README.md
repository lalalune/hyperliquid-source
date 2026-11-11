# RE-008: node #115 MessagePack struct visitor 0x332c430 is Locus, with all 16 field arms (124th stage)

- Component ID: abci. Question: open PR #6585 mapped only field 1 (`cls`) and the skip entry of the struct visitor `0x332c430`, and said the struct is `Locus` by inference. Which field arm reads which short key, which decoder does each arm call, and do fixed bytes prove the struct is `Locus`?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6585 and uses facts from open PRs #6093 (the `struct Locus with 16 elements` record) and #6097 (the Locus name block). It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, two relocations, function starts from `.eh_frame_hdr`, and strings are observations. "arm", "already seen", "duplicate block" and "decoder" are inferred labels. The binary was not executed.
- Scope included: all 17 entries of field table `0x73da1c`, the first instructions of each named arm up to its decoder call, each arm's duplicate-field block, the name block, and the call from `0x332c430` to the length helper `0x2fc21d0` with its `Locus` record. Scope excluded: the bodies of the 15 decoders, the inline value read of arm 14 (`pmu`), the key reader `0x33de700` (its slot relocation is checked, its body is not read), and the callers of `0x332c430`. No gate changes.

## Result

| Index | Key | Arm | Duplicate block (name address) | Decoder called |
|---|---|---|---|---|
| 0 | `ctx` | `0x332c7e9` | `0x3330098` (`0x794e8a`) | `0x30d1c60` |
| 1 | `cls` | `0x332d10f` | `0x332fd06` (`0x794e8d`) | `0x2f4d3e0` (type name `Clearinghouses`, #6585) |
| 2 | `scl` | `0x332cd7d` | `0x3330120` (`0x794e90`) | `0x31b5450` |
| 3 | `ftr` | `0x332cf72` | `0x33302f6` (`0x794e93`) | `0x3393070` |
| 4 | `ust` | `0x332cb63` | `0x333037e` (`0x794e96`) | `0x30afe30` |
| 5 | `chn` | `0x332d17f` | `0x333048e` (`0x794e99`) | `0x2f35c20` |
| 6 | `pdl` | `0x332d201` | `0x3330516` (`0x794e9c`) | `0x37ce740` |
| 7 | `uaR` | `0x332d051` | `0x3330406` (`0x794e9f`) | `0x32da770` |
| 8 | `blp` | `0x332d33a` | `0x33301e6` (`0x794ea2`) | `0x3309630` |
| 9 | `qus` | `0x332ccf0` | `0x332ff26` (`0x794ea5`) | `0x325ec80` |
| 10 | `ctr` | `0x332d245` | `0x332fd8e` (`0x794ea8`) | `0x32a1740` |
| 11 | `uac` | `0x332ca94` | `0x333026e` (`0x794eab`) | `0x3292600` |
| 12 | `vlt` | `0x332cc32` | `0x332fe9e` (`0x794eae`) | `0x31b4c30` |
| 13 | `hcm` | `0x332d1bd` | `0x332fe16` (`0x794eb1`) | `0x2f3afc0` |
| 14 | `pmu` | `0x332ca3c` | `0x3330010` (`0x794eb4`) | none: the value is read inline |
| 15 | `msc` | `0x332ce86` | `0x332fc7e` (`0x794eb7`) | `0x328f250` |
| 16 | (other key) | `0x332ca10` | none | `0x31d5e50` (skip) |

- Every named arm i first tests whether field i was already seen. If it was, it branches to a block that loads the name at `0x794e8a + 3*i` and stores length 3. So the key of arm i is name i of the block, for all 16 arms.
- **The struct is Locus (now proven by fixed bytes).** `0x332c430` calls `0x2fc21d0` at `0x332dd91`. `0x2fc21d0` loads the record `0x6464530` at `0x2fc2201`. That record's pointer is relocated to `0x794eba`, and its length is `0x1d`: the 29 bytes `struct Locus with 16 elements`. The 48-byte name block ends exactly at `0x794eba`. #6097 showed the same block is the Locus field-name block.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_msgpack_fields_115.py --check
python3 -m unittest tests.test_locus_msgpack_fields_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence

- `0x332c7b0`: `call [0x64e3db8]` on the key; the slot is relocated to `0x33de700`. `0x332c7d1`: the index byte through table `0x73da1c`.
- Each arm in the table above starts with an already-seen test and a `jne` (arm 14: `je`) to its duplicate block. Each duplicate block is `lea rax,[name]`, `mov [rsp+0x2f0],rax`, `mov qword [rsp+0x2f8],3`.
- Each arm except 14 then calls its decoder with the input at `[rsp+0xc70]` and the reader in `r15`. Arm 1 also passes the name `Clearinghouses` (length 0xe).
- `0x332ca10`: entry 16 calls `0x31d5e50`, the value skipper.
- `0x332dd86`: `lea rsi,[rsp+0x1c70]`, `mov rdi,rbx`, `call 0x2fc21d0`. `0x2fc2201`: `lea rdx,[0x6464530]`. The relocation at `0x6464530` points to `0x794eba`; the quadword at `0x6464538` is `0x1d`.

## Implementation and comparison

The tool pins the bytes of each of the 16 named arms up to the decoder call, plus 5 other byte runs, each with its meaning. It checks all 17 field-table entries, each arm's already-seen branch target, each duplicate block's name address and length, 15 decoder call targets, 2 more call targets, 2 `lea` targets, 2 relocations, the `Locus` record's length and text, the name block, and the function that holds 6 sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside an arm pin, the test relaxes that pin, so the derived check must catch the change. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: the MessagePack visitor `0x332c430` is the `Locus` visitor. All 16 short keys map to their arms in name-block order, and 15 of the arms are tied to one decoder each.
- Limits: the decoders are listed by address only; their bodies and value types are not read. Arm 14 (`pmu`) reads its value inline; that read is not mapped. The key reader `0x33de700` is not read. The callers of `0x332c430` are not mapped.
