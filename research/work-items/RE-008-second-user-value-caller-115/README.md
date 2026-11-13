# RE-008: node #115 path above the second per-user value visitor (122nd stage)

- Component ID: abci. Question: open PR #6582 found that `0x30bcb40` is a second visitor of the per-user value `{u, p, D, l, S, r}`, with one direct caller, `0x3314f4e` in `0x3314a40`. What reads `0x3314a40`, and which state field does this second visitor serve?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6582 and #6577. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, one relocation per expected text, function starts from `.eh_frame_hdr`, direct-call counts and strings are observations. "tuple", "sequence", "visitor", "arm", "not seen", "hash" and "insert" are inferred labels. The binary was not executed.
- Scope included: one direct call per level from `0x30bcb40` up to `0x3274e70`, the two key-matcher arms and field-table entries on that path, the other keys of the matcher `0x4458570`, and the two expected texts. Scope excluded: the bodies of `0x32e36c0`, `0x4717440` and `0x3ecd9a0`, the array forms of `0x32daf90` and `0x3274e70` (their calls are counted only), the other fields of both visitors, and the caller `0x3899fe0`. No gate changes.

## Result

| Level | Function | What it does (from fixed bytes) |
|---|---|---|
| 5 | `0x3274e70` | Key matcher `0x445d0d0`: `user_states` gives 1, any other key 0x13. Field table `0x706280` entry 1 is `0x3275984`, which calls `0x32daf90`. |
| 4 | `0x32daf90` | Key matcher `0x4458570`: `user_to_state` 0. Field table `0x723d40` entry 0 is `0x32db332`, which calls `0x3216f80`. |
| 3 | `0x3216f80` | A MessagePack array (0x90..0x9f) goes to `0x470e6c0`. A map (0x80..0x8f) goes to `0x45dd2b0`: `invalid type`, Unexpected tag 0xb (map), expected `a sequenced map`. |
| 2 | `0x470e6c0` | First capacity `min(len, 0x1c71)`, allocation `capacity * 0x98`; for each element: `call 0x3314a40`, then `0x4717440` and `0x3ecd9a0`. |
| 1 | `0x3314a40` | A tuple of two elements, expected `a tuple of size 2`: element 0 through `0x32e36c0` with length 0x14 (20), element 1 through `0x30bcb40`. |
| 0 | `0x30bcb40` | The second per-user value visitor (#6582). |

So the second visitor reads the values of `user_states.user_to_state`: a map from a 20-byte key to the per-user value, written as a sequence of pairs. This is the same field path as the first chain in #6577 (`user_states` → `user_to_state`), here as a MessagePack reader. It is not a different state type.

Other keys of `0x4458570`, from the compare bytes: `users_with_positions` 1, `check_all_users_for_liquidatables` 2, `asset_to_oi` 3, `asset_to_oi_szi` 3 (the same index, so a second name), `open_order_tracker` 4, `ar` 5, any other key 6.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/second_user_value_caller_115.py --check
python3 -m unittest tests.test_second_user_value_caller_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the tuple and the sequence

- `0x3314a9a`: in `0x3314a40`, a fixmap marker goes to `0x3314b43` and a fixarray marker to `0x3314bbf`.
- `0x3314c26`: `mov qword [rsp+0xc0],0x14`, then `0x3314c4f`: `call 0x32e36c0`, `cmp al,9`.
- `0x3314f26`: `cmp ebp,1; je 0x331566c` (only one element), then `0x3314f4e`: `call 0x30bcb40`.
- `0x3315637` and `0x331566c`: `invalid length` 0 and 1 with the expected value `0x6463fa0`. Its relocated formatter pointer `0x6463fb8` is `0x38db600`, which loads `0x7a0390` (`a tuple of size 2`, length 0x11).
- `0x470e6d6`: `cmp r14d,0x1c71`, `cmovb`. `0x470e728`: `imul r15,rbx,0x98`, then the allocator slot.
- `0x470e7f0`: per element, `dec r14d`, `call 0x3314a40` (`0x470e80b`). `0x470e9c6`: `call 0x4717440`, then `call 0x3ecd9a0`.

## Evidence 2: the sequenced map

- `0x3216fd7`: in `0x3216f80`, a fixmap marker jumps to `0x3217080` and a fixarray marker to `0x321711c`.
- `0x32170be`: the map path calls `0x45dd2b0`. `0x3217169`: the array path calls `0x470e6c0`.
- `0x45dd2b8`: `mov byte [rsp+0x38],0xb` (Unexpected tag 0xb). `0x45dd2cb`: the expected value `0x64906f0`, whose relocated formatter pointer `0x6490708` is `0x46dd930`. That formatter loads `0x7de6ec` (`a sequenced map`, length 0xf). `0x45dd303`: the template `0x44f07a` (length byte 0x0e, then `invalid type: `).

## Evidence 3: the two visitors

- `0x32db9c0`: in `0x32daf90`, `call 0x4458570` on the key, `cmp byte [rsp+0x170],9`. `0x32db31a`: the index through table `0x723d40`; entry 0 is `0x32db332`, which checks "not seen" and calls `0x3216f80` at `0x32db355`.
- `0x4458570`: the key length minus 2 selects an arm through table `0x7ce2c0`. Length 13 goes to `0x445883f`, which compares `user_to_state` byte by byte and ends `xor ecx,ecx; mov [rax+1],cl; mov byte [rax],9`.
- `0x327614f`: in `0x3274e70`, `call 0x445d0d0`, `cmp byte [rsp+0x560],9`. `0x3275237`: the index through table `0x706280`; entry 1 is `0x3275984`, which checks "not seen" and calls `0x32daf90` at `0x32759a9`.
- `0x445d0d0`: the key length minus 3 selects an arm through table `0x7ce814`. Length 11 goes to `0x445da33`, which compares `user_states` and sets index 1 (`mov cl,1`). Any other key gives 0x13 (`0x445dd6a`).

## Evidence 4: callers

- `0x30bcb40` has one direct caller (`0x3314f4e`), `0x3314a40` one (`0x470e80b`) and `0x470e6c0` one (`0x3217169`).
- `0x3216f80` has two: `0x32db355` and `0x32db1a9`, both in `0x32daf90`. `0x32daf90` has two: `0x32759a9` and `0x32766c6`, both in `0x3274e70`. The second call in each is counted, not mapped.
- `0x3274e70` has one direct caller, `0x389a09e`, in `0x3899fe0`. Not mapped.

## Implementation and comparison

The tool pins 25 instruction byte runs, each with its meaning. It checks 19 branch and call targets, 6 `lea` targets (3 with their strings), 2 relocations, 2 field-table entries, the function that holds each of 10 call sites, and the exact direct `call rel32` sites in `.text` for six functions. For 8 matcher arms it reads the length-table entry and spells the key and its index from the compare bytes. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: the second per-user value visitor (#6582) reads `user_states.user_to_state`, a sequence of (20-byte key, per-user value) pairs. A MessagePack map is refused with `a sequenced map`. This is the same field path as in #6577.
- Limits: that the 20-byte key is a user address is inferred from the field name and the length. The bodies of `0x32e36c0`, `0x4717440` and `0x3ecd9a0` are not read, so "hash" and "insert" are labels. The array forms of the two visitors, their other fields, and the caller `0x3899fe0` are not mapped. Direct-call counts cover `call rel32` only.
