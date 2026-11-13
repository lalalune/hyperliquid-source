# RE-008: node #115 Locus field `uaR` is a map from a 20-byte user key to a sequence (125th stage)

- Component ID: abci. Question: open PR #6589 showed that arm 7 (`uaR`) of the Locus MessagePack visitor `0x332c430` calls `0x32da770`, and did not read that decoder. What does `0x32da770` read: a struct, a map or a sequence, with which key and which value?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6589 and uses one fact from open PR #6584 (the 20-byte key reader `0x32e36c0` of `user_states.user_to_state`). It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, one relocation, function starts from `.eh_frame_hdr`, and strings are observations. "map visitor", "array visitor", "key reader", "refusal" and "collector" are inferred labels. The binary was not executed.
- Scope included: the marker dispatch of `0x32da770`, its map and array visitors up to their key and value calls, the key reader's length and call, the value reader `0x329edf0` up to its map and array paths, and the map refusal `0x3848e30` with its expectation text. Scope excluded: the item decoder `0x2f3c470`, the collector `0x3710120`, the array element decoder `0x3168ee0`, and what the name `uaR` stands for. No gate changes.

## Result

| Level | Function | Result |
|---|---|---|
| Locus arm 7 | `0x332d073` | `call 0x32da770` (#6589) |
| `uaR` decoder | `0x32da770` | fixmap (`0x80`-`0x8f`) goes to the map path `0x32da86e`, which calls `0x37351a0`. fixarray (`0x90`-`0x9f`) goes to the array path `0x32da91c`, which calls `0x377b070`. Marker table `0x723224`: map16 `0xde` and map32 `0xdf` join the map path, array16 `0xdc` and array32 `0xdd` join the array path. |
| Map visitor | `0x37351a0` | Key through `0x2f660a0` with the 4-byte type name `User`; value through `0x329edf0`. Loads `duplicate key`. |
| Key reader | `0x2f660a0` | Stores length `0x14` (20 bytes) and calls `0x32e36c0`, the same reader that `0x3314a40` calls for the `user_to_state` key (#6584) |
| Array visitor | `0x377b070` | Each element through `0x3168ee0`. Loads `duplicate key`. |
| Value reader | `0x329edf0` | fixmap goes to `0x3848e30`. fixarray goes to a loop that reads each item through `0x2f3c470` and adds it through `0x3710120`. |
| Map refusal | `0x3848e30` | Unexpected-type tag `0xb` (map), text `invalid type: `, expectation record `0x646c990`. The record's first method (relocated slot `0x646c9a8` -> `0x38db620`) writes `a sequence` (length 10). |

- So Locus field `uaR` is a map. Its key is a 20-byte `User` key, read by the same reader as the `user_to_state` key. Its value is a sequence of items; a MessagePack map in that place is refused with `expected a sequence`.
- Inferred, not proven: that the 20-byte key is a user address (from the type name and the length), and that the outer map keeps keys in order (from the `duplicate key` text).

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_uar_115.py --check
python3 -m unittest tests.test_locus_uar_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The twelve `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 15 byte runs, each with its meaning. It checks 16 call and jump targets, 4 marker-table entries with the first bytes and the join jump of each wide arm, 6 `lea` targets (4 with strings), 1 relocation, and the function that holds 15 sites. Tests change bytes in a copy of the image (or a relocation addend) and expect rejection with a named reason. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: Locus field 7 (`uaR`) is a map from a 20-byte `User` key to a sequence of items.
- Limits: the item decoder `0x2f3c470`, the collector `0x3710120` and the array element decoder `0x3168ee0` are listed by address only. The meaning of the short key `uaR` is not proven. Arm 14 (`pmu`) is not covered here.
