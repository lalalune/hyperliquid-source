# RE-008: node #115 ExchangeMisc field offsets and the field `i` stop byte (stage 91)

- Component ID: abci. Question: stage 90 (open PR #6098) typed Exchange field `msc` as `struct ExchangeMisc with 12 elements` and placed field `i` at msc+0xa0/+0xa8 (box +0x39a8/+0x39b0). It left open the offsets of the other 11 fields and what `i`'s byte means at the six simulate-panic sites from #6091.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6091 and #6098; it does not depend on their files.
- Claim status: instruction bytes, jump-table entries, call targets, stack offsets, string bytes and FDE extents are observations. "Option", "bool", "Vec-like", "default" and the field type hints are inferred labels from sizes, sentinel values and decoder shapes. The binary was not executed.
- Scope included: the map-form path of the visitor 0x490d9b0 (field switch, one case per field, the assembly of the 0xf8-byte output), the nil branch of the field `i` decoder 0x47922c0, and the stop-byte instruction at each of the six simulate-panic sites. Scope excluded: the bodies of the 11 other decoders, the array-form path of the visitor, the inner decode of `i` (slot 0x64e2598), and `struct LocusMisc`.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/exchange_misc_offsets_115.py --check
python3 -m unittest tests.test_exchange_misc_offsets_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: the field switch

After the field-identifier call, `0x490dc41` loads jump table `0x825408` and jumps on the field index. Entries 0..11 are the 12 field cases, entry 12 is the unknown-field case `0x490de0b`. Each case checks for a duplicate, calls one decoder and stores its result into fixed stack slots (pinned in the tool). `mtpt` is decoded through slot `0x64dfeb0`; the others through direct calls.

## Evidence 2: the 0xf8-byte output

The visitor builds the struct at `rsp+0x2e8` and copies 0xf8 bytes from there to the output (`0x490f33a`, `0x490f342`). Following each field's stack slot into that buffer gives:

| Index | Name | Struct offset | Box offset (layout A) | Size | Decoder | Type hint | When absent |
|---|---|---|---|---|---|---|---|
| 2 | sgd | +0x00 | +0x3908 | 0x10 | 0x4d440e0 | Option<f64> (tag, f64) | tag 0 |
| 1 | mou | +0x10 | +0x3918 | 0x50 | 0x49a7790 | 0x50-byte Option-like, None 0x8000000000000000 | None |
| 0 | uta | +0x60 | +0x3968 | 0x20 | 0x4acc0f0 | Option-like, None 0x8000000000000001 | None |
| 10 | vpv | +0x80 | +0x3988 | 0x20 | 0x4b250d0 | four words (Vec-like) | {0, 4, 0, 0} |
| 6 | i | +0xa0 | +0x39a8 | 0x09 | 0x47922c0 | (u64 height, byte), None byte 2 | byte 2 |
| 3 | sog | +0xb0 | +0x39b8 | 0x10 | 0x47b2fe0 | BucketGuard (name at 0x93a3c8), two words | first word 3000 |
| 11 | aci | +0xc0 | +0x39c8 | 0x08 | 0x4ff2810 | u64 | 1000 when 0 |
| 7 | mtpt | +0xc8 | +0x39d0 | 0x08 | slot 0x64dfeb0 | u64 | 1000 |
| 9 | sre | +0xd0 | +0x39d8 | 0x18 | 0x4af3450 | three words | zeros |
| 8 | pmc | +0xe8 | +0x39f0 | 0x0c | 0x4e36ad0 | dword + qword | dword 0xf6401a, qword 0 |
| 4 | tde | +0xf4 | +0x39fc | 0x01 | 0x586a170 | bool | false |
| 5 | tce | +0xf5 | +0x39fd | 0x01 | 0x586a170 | bool | true |

The tool checks that the spans do not overlap, end within 0xf8, and that every one of the 28 pinned output stores lands inside one span.

## Evidence 3: field `i`'s byte at the six simulate-panic sites

- The decoder `0x47922c0` writes byte 2 for msgpack nil (`cmp al,0xc0` / `mov byte [rbx+0x10],2`); otherwise it stores the byte returned by its inner decode.
- Begin A `0x5483903`, begin B `0x5484003` and `0x2bdf30d` test `byte & 1` and arm when it is set.
- Builders B `0x5488ed4`, A `0x548bfc9` and `0x2c7444e` compare the byte with 0 and arm when it equals 0.
- All six also require height == stored height and the Locus `chn` byte != 3 (#6091, #6097).
- So byte 1 arms the three begin-side sites, byte 0 arms the three builder-side sites, and byte 2 (absent field) arms none. This replaces #6091's open "opposite polarity" question: the two groups test different byte values, not opposite readings of one flag.

## Results and limitations

- Result: the 12 ExchangeMisc fields have byte offsets inside box +0x3908..+0x3a00; field `i` is (height, byte) with three states.
- Limits: the bodies of the 11 other decoders, so the type hints are labels; the second word of `sog` when absent (computed from data at 0x464984); the array-form path; the inner decode of `i`; which code path the 0/1 states are meant for beyond the site names; `struct LocusMisc`.
- Next lead: the inner decode of `i` (slot 0x64e2598) to name the byte, and the array-form path for the same layout.
