# RE-008: node #115 Locus field `pmu` is a required non-negative integer (127th stage)

- Component ID: abci. Question: open PR #6589 mapped the 16 field arms of the MessagePack Locus visitor `0x332c430`, and noted that arm 14 (`pmu`, at `0x332ca3c`) calls no separate decoder. What does arm 14 read, and what happens when `pmu` is repeated or missing?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6589. It does not depend on its files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, one relocation, function starts from `.eh_frame_hdr`, and strings are observations. "u64 visitor", "seen flag" and "error builder" are inferred labels. The binary was not executed.
- Scope included: Locus arm 14, its duplicate and missing-field paths, and the value reader `0x14b7aa0` up to its marker table and result tags. Scope excluded: the error builder `0x3046740` body, the other Locus fields (`scl` was looked at only at its first marker dispatch and is not packaged), and what the name `pmu` stands for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Duplicate check | `0x332ca3c` | If the seen flag at `rsp+0xa0` is 1, jump to `0x3330010`, which loads the name `pmu` (`0x794eb4`, length 3) for the duplicate-field error |
| Value read | `0x332d81a` | Calls the value reader through slot `0x64dfeb0`. The slot has one `R_X86_64_RELATIVE` relocation to `0x14b7aa0`. |
| Keep the value | `0x332d830` | On result tag 9, keeps the 8-byte value at `rsp+0x2a8` and sets the seen flag to 1 |
| Missing field | `0x332fb72` | If the seen flag is still 0 at the end, loads `pmu` and the template `missing field `...`` (`0x4325c4`) and calls `0x3046740`. No default value is stored. |

Value reader `0x14b7aa0` (marker table `0x462eb4`, markers `0xc0` to `0xe0`):

| Marker | Arm | Result |
|---|---|---|
| positive fixint, `0xcc` u8, `0xcd` u16, `0xce` u32, `0xcf` u64 | `0x14b7b9e`, `0x14b7b77`, `0x14b7be9`, `0x14b7b54`, `0x14b7cc0` | Number stored, tag 9 (`0x14b7d0e`) |
| `0xd0` i8 to `0xd3` i64, negative fixint | `0x14b7c5c`, `0x14b7bb2`, `0x14b7b1b`, `0x14b7c8d`, `0x14b7b9e` | Kept when >= 0. A negative value is reported as an unexpected signed integer (tag 2, `0x14b7d5a`) |
| `0xca` f32 | `0x14b7ac5` | Widened, reported as an unexpected float (tag 3, `0x1516602`) |
| `0xcb` f64 | `0x14b7c1e` | Arm listed; body not pinned |
| `0xc2` false, `0xc3` true | `0x14b7d2f`, `0x14b7d2b` | Reported as an unexpected bool (tag 0, `0x1513c8d`) |
| `0xc0` nil, other markers | `0x14b7d1a`, `0x14b7b09` | Rejected |

- So `pmu` is a required field holding one non-negative integer, read the way a `u64` is read. It has no default.
- Inferred, not proven: the Rust type name (`u64`) and what `pmu` stands for.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_pmu_115.py --check
python3 -m unittest tests.test_locus_pmu_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eight `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 17 byte runs, each with its meaning. It checks 4 branch and call targets, 4 `lea` targets (3 with their strings), the slot call and its relocation, 15 marker-table entries, and the function that holds 10 sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: Locus field 14 `pmu` is a required non-negative integer; a repeated `pmu` and a missing `pmu` are both errors.
- Limits: the error builder `0x3046740`, the other Locus fields, and the meaning of `pmu` are not mapped.
