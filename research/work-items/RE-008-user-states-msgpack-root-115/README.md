# RE-008: node #115 MessagePack path above user_states reaches cls (123rd stage)

- Component ID: abci. Question: open PR #6584 found that the `user_states` reader `0x3274e70` has one direct caller, `0x389a09e` in `0x3899fe0`, and left it unmapped. What reads `0x3899fe0`, and which field of which struct holds this path?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6584 and #6577. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, one relocation, function starts from `.eh_frame_hdr`, direct-call counts and strings are observations. "sequence", "newtype", "visitor", "arm" and "not seen" are inferred labels. That the 16-field struct is `Locus` is an inference from its field names and count. The binary was not executed.
- Scope included: one direct call per level from `0x3274e70` up to `0x332c430`, field 1 and field 16 of the struct visitor's field table, the 48-byte block of 16 field names, the `cls` duplicate-field name, and the type name `Clearinghouses`. Scope excluded: the key reader `0x33de700` (its slot relocation is checked, its body is not read), the other 15 fields and their arms, the map-form error text beyond `invalid type: `, and the two callers of `0x332c430`. No gate changes.

## Result

| Level | Function | What it does (from fixed bytes) |
|---|---|---|
| 4 | `0x332c430` | Struct visitor. The key goes through slot `0x64e3db8` (relocated to `0x33de700`), then table `0x73da1c`. Entry 1 is `0x332d10f`: not-seen check, name `Clearinghouses` (length 0xe), `call 0x2f4d3e0`. A second `cls` is reported with the 3-byte name `cls` (`0x794e8d`). Entry 16 skips the value (`0x31d5e50`), so fields 0 to 15 are named. |
| 3 | `0x2f4d3e0` | A MessagePack array (0x90..0x9f) goes to `0x3899fe0`. A map (0x80..0x8f) goes to `0x384c960`, which reports `invalid type`. |
| 2 | `0x3899fe0` | First capacity `min(len, 0x329)`, allocation `capacity * 0x510`; for each element `call 0x3274e70`. |
| 1 | `0x3274e70` | Holds `user_states` as field 1 (#6584). |

The 48 bytes at `0x794e8a` are sixteen 3-byte names: `ctx cls scl ftr ust chn pdl uaR blp qus ctr uac vlt hcm pmu msc`. The struct visitor references this block for its duplicate-field errors, and field 1 is `cls`.

## The full MessagePack chain (#6580, #6581, #6582, #6584 and this stage)

| Step | Function | Key or form | Stage |
|---|---|---|---|
| struct (Locus by inference) | `0x332c430` | field 1 `cls`, type `Clearinghouses` | this stage |
| newtype | `0x2f4d3e0` | array of clearinghouses; a map is refused | this stage |
| sequence | `0x3899fe0` | one `0x510`-byte element per entry | this stage |
| clearinghouse | `0x3274e70` | field 1 `user_states` | #6584 |
| user states | `0x32daf90` | field 0 `user_to_state` | #6584 |
| sequenced map | `0x3216f80` → `0x470e6c0` | (20-byte key, value) pairs; a map is refused | #6584 |
| pair | `0x3314a40` | element 1 is the per-user value | #6584 |
| per-user value | `0x30bcb40` | `u p D l S r`; `p` through `0x3184540` | #6582 |
| `p` value | `0x3184540` → `0x314bba0` | `p`/`perp_to_position`, `n`/`n_open_positions`; map of `Perp` → position | #6581 |
| position | `0x32d3c90` | `s l M f e`; `M` nonzero u32, default 20 | #6580 |

So the MessagePack reader reaches each position through `cls[i].user_states.user_to_state[user].p.p[perp]`. The JSON writer in #6577 writes the same keys (`locus`, `user_states`, `user_to_state`).

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_states_msgpack_root_115.py --check
python3 -m unittest tests.test_user_states_msgpack_root_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence

- `0x3899ff6`: `cmp ebp,0x329`, `cmovb`. `0x389a014`: `imul rbx,r15,0x510`. `0x389a060`: each element is stored at `index * 0x510` with a 0x510-byte copy. `0x389a09e`: `call 0x3274e70`.
- `0x2f4d4ae`: `cmp cl,0x90; jae`; fixmap jumps to `0x2f4d5ae`. `0x2f4d4d0`: `cmp cl,0xa0; jae`; fixarray jumps to `0x2f4d630`.
- `0x2f4d5b1`: depth check, then `call 0x384c960` (`0x2f4d5dd`). `0x2f4d630`: depth check, then `call 0x3899fe0` (`0x2f4d668`).
- `0x384c9a3`: `0x384c9af` loads the template `0x44f07a` (length byte 0x0e, then `invalid type: `), then `call 0x3046740`.
- `0x332c7b0`: `call [0x64e3db8]` on the key; the slot is relocated to `0x33de700`. `0x332c7d1`: the index byte through table `0x73da1c`.
- `0x332d10f`: `cmp [rsp+0x1d8],r13; jne 0x332fd06`, `mov ecx,0xe`, `lea rdx,[0x7d23bf]` (`Clearinghouses`), `call 0x2f4d3e0` (`0x332d134`).
- `0x332fd06`: `lea rax,[0x794e8d]`, length 3: the duplicate-field name `cls`.
- `0x332dba4`: the array form of the struct visitor passes the same name and calls `0x2f4d3e0` (`0x332dbbb`).
- `0x332ca10`: entry 16 calls `0x31d5e50`, the value skipper also used in #6582.
- Direct callers: `0x3274e70` only `0x389a09e`; `0x3899fe0` only `0x2f4d668`; `0x384c960` only `0x2f4d5dd`; `0x2f4d3e0` `0x332d134` and `0x332dbbb`; `0x332c430` `0x2fd78dc` (in `0x2fd7260`) and `0x32cb193` (in `0x32caf70`), not mapped.

## Implementation and comparison

The tool pins 15 instruction byte runs, each with its meaning. It checks 10 branch and call targets, 4 `lea` targets with their strings, the 48-byte name block, 1 relocation, 2 field-table entries, the function that holds each of 7 call sites, and the exact direct `call rel32` sites in `.text` for five functions. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: the `user_states` reader is reached through field 1 (`cls`) of a 16-field struct, as a sequence of `0x510`-byte clearinghouse values. With #6580 to #6584 this closes the MessagePack path from that struct down to a position's fields.
- Limits: the key reader `0x33de700` is not read, so the key-to-index mapping is shown for `cls` only, through the field table and the duplicate-field name. That the struct is `Locus` and that the JSON writer's `locus` field holds the same value are inferences. The callers of `0x332c430` and the other 15 fields are not mapped. Direct-call counts cover `call rel32` only.
