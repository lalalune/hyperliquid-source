# RE-008: node #115 callers of the second MessagePack position decoder (120th stage): the map and array forms of a second `p` decoder

- Component ID: abci. Question: open PR #6580 found that `0x32d3c90` is a second MessagePack position decoder (success tag 9) and named its two direct callers, `0x318126c` and `0x372f3ae`, without mapping them. Which structure does each caller serve?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6580 and #6239. It does not depend on their files.
- Claim status: instruction bytes, branch and call targets, function starts from `.eh_frame_hdr`, direct-call counts and strings are observations. "map form", "array form", "visitor", "not seen" and the field names are inferred labels. The binary was not executed.
- Scope included: the two callers and the functions that hold them, the visitor above each, their common caller `0x314bba0`, the function above that (`0x3184540`) and its key matcher `0x2fd31e0`, and a count of the direct callers at each level. Scope excluded: the element body of `0x3180b40` beyond its call to `0x32d3c90`, the `Perp` key reader `0x2f48380`, the second field of `0x3184540`, where the decoded values are stored, and the function `0x30bcb40` above `0x3184540`. No gate changes.

## Result

| Level | Function | What fixed bytes show |
|---|---|---|
| Caller `0x372f3ae` | `0x372f280` | Map-form visitor. For each entry: key through `0x2f48380` with the name `Perp` (4), tag 9, then the value through `0x32d3c90`. Entries are 0x48 bytes (`lea rcx,[rbx+rbx*8]`, store at `[rax+rcx*8]`). |
| Caller `0x318126c` | `0x3180b40` | Element decoder. Its only direct caller is `0x37b7b6e` in `0x37b7a80`, the array-form visitor. |
| Common caller | `0x314bba0` | Reads one MessagePack marker. Below `0x90` (fixmap) it calls `0x372f280`; `0x90` to `0x9f` (fixarray) it calls `0x37b7a80`. |
| Above that | `0x3184540` | Reads keys with `0x2fd31e0` (tag 9): `p` and `perp_to_position` give 0, `n` and `n_open_positions` give 1, any other key gives 2. It calls `0x314bba0` twice: once after a not-seen check (`0x318480b`), once after a non-zero length check (`0x3184deb`). |
| Boundary | `0x30bcb40` | Holds both direct calls to `0x3184540` (`0x30bd552`, `0x30be015`). Not mapped. |

So both callers serve one field: the perp-to-position map inside a `p` value. `0x372f3ae` is the map form of that map and `0x318126c` is its array form. The keys of `0x3184540` are the keys of the per-user `p` field decoder `0x191bf90` in #6239, so `0x3184540` is a second decoder of the same `p` value, built for the tag-9 result type of #6580.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_decoder_callers_115.py --check
python3 -m unittest tests.test_position_decoder_callers_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the map-form visitor `0x372f280`

- `0x372f384`: `lea rdx,[0x45a0d0]` (`Perp`, length 4 in `ecx`), `call 0x2f48380`, `cmp al,9; jne`.
- `0x372f3ae`: `call 0x32d3c90`, then `cmp r13d,2` on the result.
- `0x372f305`: `lea rcx,[rbx+rbx*8]`, `mov [rax+rcx*8],r12`, `mov [rax+rcx*8+0x8],r13d`: entry `rbx` starts at `rbx * 0x48`.

## Evidence 2: the array form

- `0x37b7b6e` in `0x37b7a80`: `call 0x3180b40` once per element (element count in `ebp`, decremented before the call), then `cmp r13d,2` on the result.
- `0x318126c` in `0x3180b40`: `call 0x32d3c90`.

## Evidence 3: the common caller `0x314bba0`

- `0x314bbf5`: `cmp al,0x90; jae 0x314bc03`; below it, `jmp 0x314bc9e`. `0x314bc03`: `cmp al,0xa0; jae`; below it, `jmp 0x314bd4c`.
- `0x314bcd5` (on the `0x314bc9e` path): `call 0x372f280`. `0x314bd83` (on the `0x314bd4c` path): `call 0x37b7a80`.

## Evidence 4: the `p` decoder `0x3184540`

- `0x3184af5`: `call 0x2fd31e0` on the key; `cmp byte [rsp+0x38],9`.
- `0x2fd31e0`, key length 1: `n` gives 1, `p` gives 0, other gives 2. Key length 16: the compare bytes spell `perp_to_position` (result 0) and `n_open_positions` (result 1); any mismatch gives 2. Every exit stores tag 9.
- `0x31847e9`: `cmp [rsp+0x18],0x8000000000000001; jne` (duplicate), then `0x318480b`: `call 0x314bba0`.
- `0x3184dd6`: `test ebp,ebp; je`, then `0x3184deb`: `call 0x314bba0`.

## Implementation and comparison

The tool pins 10 instruction byte runs and the whole key matcher (0x139 bytes), each with its meaning. It spells the two 16-byte keys from the matcher's compare bytes. It checks 12 call and branch targets, one `lea` with its string, the function that holds each of 10 call sites (from `.eh_frame_hdr`), and the exact list of direct `call rel32` sites in `.text` for six functions. Tests change bytes in a copy of the image and expect rejection with a named reason. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternative considered: running the decoder on a sample input (not allowed for this repository).

## Results and limitations

- Result: the two callers of the second position decoder are the map form and the array form of one perp-to-position map decoder, `0x314bba0`, which is field 0 of a second `p` decoder, `0x3184540`.
- Limits: which top-level structure holds this second `p` decoder is not shown; `0x30bcb40` is not mapped. The `Perp` key reader `0x2f48380`, the element body of `0x3180b40`, field 1 (`n`) of `0x3184540` and the store offsets are not read. Direct-call counts cover `call rel32` only; calls through slots or tables are not counted.
