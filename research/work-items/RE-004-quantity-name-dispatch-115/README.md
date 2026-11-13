# RE-004: node #115 quantity-name dispatcher 0x2913750 as an executable flow model

- Component ID: RE-004 (assets / outcome-deploy quantities, `l1/asset/pdi.rs`, `l1/spot_meta.rs`, `l1/exchange/impl_outcome_deploy.rs`, `base/l1_map/entry.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Source commit: `a8616af9432b8d8517b2af677880e117b7c28ef3` (base of this workspace)
- Claim status: observation (control flow, constants, argument and result routing, checked arithmetic); inference (roles of the callees and of the 100000 / 10000 constants); unresolved (callee behaviour, arms 7 and above)
- Scope included: the whole FDE `0x2913750..0x2914169` (2,585 bytes, 500 instructions) and the range-generation body `0x22b3160..0x22b3298` (312 bytes, 93 instructions) that it calls; the six-way jump table at `0x5fd4bc`. Excluded: the bodies of `0x2c51ab0`, `0x2c59960`, `0x2dc7ad0`, `0x2c4fcd0`, `0x28cd7a0`, `0x43cd290`, `0x2bee760`, `0x29330f0` and the eight GOT slots, which are treated as opaque calls; the unwinding landing pads' behaviour; every jump-table arm at or above index 7; Rust types. No gate is requested.

The dispatcher `0x2913750` is a seven-arm decision procedure over an enum word at `[rsi]` whose arithmetic is now pinned and executable: arm 0 narrows a parsed integer `v` to `v` (v <= 9999), `v + 100000` (v <= 0x5f45a5f) or `0xffffffff`, arm 4 divides a word by 10000 with the reciprocal `0x346dc5d63886594b >> 75`, and arm 3 expands a record into the ids `10000 * [rec+0x50] + i` through `0x22b3160`, so a reconstruction can now write the whole routing, length gates (`< 0x65`), sentinel tests and error-tag choices as a pure function and check it against the bytes (10,282 cases, 49/49 byte mutants caught).

All addresses are ELF virtual addresses. `.text` bytes are read through the shared ELF/FDE parsers; the node is never executed.

## Reproduce

```
python3 tools/quantities_dispatch115.py --out research/work-items/RE-004-quantity-name-dispatch-115
python3 -m unittest tests.test_quantities_dispatch115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool fails when the SHA-256 of `artifacts/node/115/hl-node` differs from the value above. One regeneration takes about 25 s and well under 200 MB. `cases.tsv` keeps every fifth case line (the others are regenerated); `cases_sha256` in `measure.json` is the digest over all 10,282 lines. The tests read `code-bytes.json` (the two function bodies and the table, as raw hex) and run without the binary.

Objdump cross-check used while analysing (not used by the tool): `objdump -d -M intel --start-address=0x2913750 --stop-address=0x2914169 artifacts/node/115/hl-node`.

## Evidence

Files (all produced by the tool, byte for byte):

| file | content |
| --- | --- |
| `instructions.tsv` | decoder rows for both extents; last column = executed by at least one case |
| `call-sites.tsv` | every call site (17 direct, 25 through a GOT slot `call [rip+disp]`) with the role letter used below |
| `jump-table.tsv` | table entries `0x5fd4bc + int32[i]`, whether the target is inside the FDE |
| `cases.tsv`, `range-cases.tsv` | per-case input summary, outcome, output tag, call count, steps, call-log digest |
| `controls.tsv`, `equivalent-mutants.tsv`, `measure.json` | 49 byte mutants and the measured summary |
| `canonical-traces.md` | 20 canonical emulator runs (every arm, each failure branch) as call lists with the result tag |
| `code-bytes.json` | raw bytes of `0x22b3160`, `0x2913750` and the table (fixture for the tests) |

Dispatch (observed, `0x291375a..0x291379a`): `idx = T - (2^63 + 13)` when `T > 2^63 + 12` (unsigned), else `idx = 5`; target = `0x5fd4bc + int32[idx]`. Entries 0..6 are `0x291379c 0x29139a9 0x29138e9 0x2913979 0x291388c 0x29139ee 0x2913a49`, all inside the FDE; entries 7..13 begin `0x291d6c7 0x291d72d 0x291d6d0 0x291d711 0x291d917 ...` outside it. The table has no bounds check, so its length is unresolved; `jump-table.tsv` lists the 69 consecutive entries that stay within `0x2900000..0x2930000` as a heuristic window, not a claim. Tag word `T <= 2^63 + 12` is the dataful variant (arm 5), consistent with a String-like capacity niche.

Arms (role letters: `S` = `0x43cd290`; `A..G` = GOT slots `0x64e6a68 0x64e69b8 0x64e4e58 0x64e6c18 0x64e6c20 0x64e6ad8 0x64e6c28`; `H` = `0x2c4fcd0`; `W` = `0x28cd7a0`; `X` = `0x2dc7ad0`; `Y` = `0x2c51ab0`; `Z` = `0x2c59960`). Result record is 0x70 bytes at `rdi`; `0x1a2` is the success tag word, any other word is an error that is copied verbatim.

| arm | input fields (offset from `rsi`) | flow |
| --- | --- | --- |
| 0 | cap `+8`, ptr `+0x10`, len `+0x18` | len >= 0x65: free(ptr,cap) if cap != 0, tag `0x158`, `[out+0x18] = len`. Else `S(ptr,len,0,len,0x3a0000003a,1)`; `A(ctx+0x7c0, found ? ptr : 1, found ? pos : 0)`; `B(ptr, len, A.word)`; any non-`0x1a2` tag is returned as is; the parsed integer goes through the narrowing below, then `W{tag 0x35, id:u32, 1}`; free(ptr,cap) at the end. |
| 1 | 21 bytes at `+8` | `W{tag 0x2d, the 21 bytes}` |
| 2 | 24 bytes at `+8` | `C(24 bytes)`; error: free the 24-byte string (cap `+0`, ptr `+8`) and return it; success: `X(ctx+0x338, the 24 bytes, in+0x20)`, tag `0x1a2` |
| 3 | cap, ptr, len as arm 0; flag byte `+0x20` | len >= 0x65: free, tag `0x158` (no length stored). `D(ctx+0x7c0, ptr)` gives a record R; `[R+0x378] == 2^63`: tag `0x156`. Else flag set: `[R+0x468] = 2`, range body over `[0, [R+0x10])`, `VIS(ctx, id)` for each id, free the id vector; flag clear: `[R+0x468] = 0`. Name freed at the end. |
| 4 | 24-byte string `+8`, flag `+0x20` | `H(string)` gives R and a word `w` at `+0x10`; `[R+0x378] == 2^63`: tag `0x156`; `[R+0x408] != 2^63 + 1`: tag `0x1a1`; else `E(R+0x378, w)` returns byte `al`; flag clear: call `G` unless `al == 2` (mode 2); flag set: call `G` only if `al == 2` (mode 1); `G(F(ctx+0x7c0, w / 10000), w, mode)` where the division is `(w * 0x346dc5d63886594b) >> 75`; the string is freed in every case. |
| 5 | whole 0xb0 record | memcpy 0xb0 bytes to a local, `Z(ctx, 20 zero bytes, copy)`, error record returned, `DROP(copy)` |
| 6 | index `+8` | `v >= [ctx+0xb8]`: tag `0xfa`, `[out+8] = v`. Else `Y(ctx, [in+8..+0x60))` |

Narrowing in arm 0 (`0x2913879..0x291408b`): `cmp rax, 0x270f; ja` keeps `v` for `v <= 9999`; otherwise `cmp rax, 0x5f45a5f; jbe` adds `0x186a0` (100000) to the low 32 bits, else the result is `0xffffffff`. So 10000 maps to 110000 and `0x5f45a5f` (99,899,999) to 99,999,999; the next value gives `0xffffffff`.

Range body (`0x22b3160`, already observed in the existing `RE-004-node115-pdi-range` packet): this packet adds the exact wrap rule `((a + 10000 * s) + i) mod 2^64 < 10000 * s` for the add guard (a is the range start, s the word at `[rec+0x50]`), checked for starts near 2^64, and the `n >= 2^60` allocation refusal.

Excerpt (arm 0 narrowing):

```
2913879: cmp    rax,0x270f
291387f: ja     2913fa8
2913fa8: mov    ecx,0xffffffff
2913fad: cmp    rax,0x5f45a5f
2913fb3: jbe    291408b
291408b: add    eax,0x186a0
2914090: jmp    2913885
```

## Implementation and comparison

`tools/quantities_dispatch115.py` contains (1) the shared offline interpreter, (2) a pure Python model of the dispatcher (`model`, `model_range`, `asset_id`, `arm_index`) written from the table above, and (3) the harness that runs `0x2913750` and `0x22b3160` on the interpreter with the callees served by recording stubs. Each stub returns a 0x70-byte record derived from a hash of the arguments it received, so a wrong argument, wrong order or wrong copy changes the result bytes; the model derives the same record from the arguments it expects. A case passes only if the outcome kind (return, panic at the multiply / add / allocation-error slot, or arrival at a jump-table target outside the FDE), the full call log (callee, argument registers, memory snapshots, free sizes), the output record bytes and the record byte `+0x468` all equal the model.

Cases: 10,282 in total, by arm: 0: 2,472; 1: 60; 2: 40; 3: 1,679; 4: 4,313; 5: 49; 6: 951; 187 jump-table arrivals (indices 7..68); 531 direct calls of the range body with starts and ends near 0, 2^63 and 2^64. Of these, 6,000 are seeded random cases (arms 0, 3, 4, 6) and the rest are enumerated boundary combinations (lengths 0..2^64-1, cap zero / nonzero, success or failure of each callee, 13 parsed values around 9999, 10000 and `0x5f45a5f`, 1,617-element products at the add-guard edge, range sizes 2^60-1, 2^60 and 2^61).

Negative controls: 49 byte patches (condition inversions, immediates +-1, wrong displacements, wrong tags, reciprocal constant and shift, swapped compare operands, etc.). Each original byte string is asserted before patching. The tests also reject wrong Python variants of the narrowing and the length gate, a corrupted fixture byte, and a wrong binary digest.

## Results and limitations

- `measure.json`: cases 10,282; negative_controls 49; negative_detected 49; equivalent 0; outcomes ret 9,758, panic 337, trap 187; instructions executed 528 of 593.
- Unexecuted instructions are the tails after the non-returning allocation-error / panic calls in `0x22b3254..0x22b3293`, and the cleanup landing pads `0x2914095..0x2914164`, reachable only by unwinding. Their behaviour is not modelled.
- The callee stubs are synthetic. The check proves the dispatcher's own routing, gates, arithmetic and ownership of buffers given those calls, not what the callees compute. The role letters are labels for call sites, not recovered function identities.
- The model and the harness share the stub record function, so a mistaken belief about a callee's output layout would pass; only the reads the dispatcher performs (`+8` pointer, `+0x10` word, byte at `+8`) are observations.
- `100000 + 10000 * dex + index` as the id layout is an inference from the 100000 offset of arm 0, the 10000 stride of the range body and the `/ 10000` of arm 4; no callee was decoded to confirm it.
- Arms 7 and above are outside this FDE and are only checked to land on their table targets. The relation to the vaults component is not established by this work.
- Next question: what do `0x2c4fcd0` (arm 4's record lookup, returns R with the `+0x378` / `+0x408` words) and slot `0x64e6c20` compute, and is the arm at `0x291d6c7` the sibling that reuses the same `0x28cd7a0` encoder.
