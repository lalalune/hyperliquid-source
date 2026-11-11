# RE-008: node #115 per-user value field `l` is read as a formatted date and time string (133rd stage)

- Component ID: abci. Question: open PRs #6239 and #6582 showed that both per-user value visitors read field `l` through a decoder that is given the 4-byte name `Time`. What does that decoder accept, and what does `Time` mean?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6239 and #6582. It does not depend on their files.
- Claim status: instruction bytes, branch and call targets, RIP-relative references, relocations, function extents from `.eh_frame_hdr`, and strings are observations. "newtype" is an inferred label. The binary was not executed.
- Scope included: the two call sites, the name check and value read in both `l` decoders, the slot relocation, the f32 arm of the reader, and the expected text of its error. Scope excluded: field `u`, the f64 arm and other markers, the rest of the decoder bodies. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Callers | `0x1a221f0` in `0x1a212f0` (#6239); `0x30bd6cf` in `0x30bcb40` (#6582) | Call `0x17ce890` and `0x2f6fa30`. Both pass the name `Time` (`0x459f78`) with length 4. |
| Decoder size | `0x17ce890`, `0x2f6fa30` | Both unwind extents are `0xa00` bytes |
| Name check | decoder `+0x10`, `+0x16`, `+0x27` | Each compares the name length with 10 and the name with `_ExtStruct`, the MessagePack extension newtype name. `Time` is not that name, so `Time` is the newtype name the caller passes, not a value. |
| Value read | decoder `+0x150` | Both call through slot `0x64dfec0`. Its single `R_X86_64_RELATIVE` relocation points to the reader `0x14b93c0`. |
| Marker dispatch | `0x14b93c5`, table `0x463358` | Markers `0xc0` to `0xe0` go through the table. The f32 marker `0xca` goes to `0x14b93e5`. |
| f32 | `0x14b93e5` → `0x155d7e0` | Reads 4 bytes, widens the float (`0x155d7e8`), stores tag 3 (an unexpected float, `0x155d7f2`) and passes the expected-text vtable `0x63fe1f0` (`0x155d801`) |
| Expected text | `0x63fe208` → `0x1560950` | The vtable entry at `+0x18` has a single `R_X86_64_RELATIVE` relocation to `0x1560950`. That function loads `0x457c60` with length `0x20`: `a formatted date and time string`. |

So field `l` in both per-user value visitors is a newtype named `Time`, and its value reader rejects an f32 with the error text `a formatted date and time string`. This is the first string-backed meaning for `l`; #6239 named it only by its raw bytes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_l_time_115.py --check
python3 -m unittest tests.test_user_value_l_time_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The nine `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 4 byte runs in the reader path and 4 at the same offsets in each decoder, each with its meaning. It checks 2 call targets with their name length, 5 RIP-relative loads, 2 relocations, 1 jump-table entry, 2 strings, and the unwind extents of 7 functions. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: field `l` holds a date and time, by the reader's own expected text.
- Limits: what the reader does with a string, an f64 or an integer is not checked. Field `u` is out of scope.
