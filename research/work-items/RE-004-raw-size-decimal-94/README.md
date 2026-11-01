# RE-004: raw size fields and their unsigned decimal digit path

Node #94 passes the raw 64-bit `sz`, `executed_sz` and `order_sz` fields to an integer digit writer without a decimal scale, so reconstruction of these state serializers can preserve all 20 decimal digits rather than applying the order-wire price/size conversion.

- Component ID: RE-004, quantities and rounding, raw size representation.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not copied implementation.
- Claim status: byte observations and arithmetic identities below; field types and serializer roles are inferences; caller input restrictions and complete error effects remain unresolved.
- Scope included and excluded: five field-to-digit-writer sites, two outer-to-nested schedule edges, the writer's digit construction and buffer branch, the full pair table, and its arithmetic bounds. Excluded: compact order-wire output, other fields and callers, growth and copy helper internals, target execution, and node #115.

## Reproduce

From the repository root, Python 3.12.3 and the standard library suffice. The generator checks the complete target digest, imports the common ELF and FDE parsers, reads file-backed sections and writes only the two generated evidence files. It does not execute the artifact or invoke external programs. GNU objdump 2.42 was used only for the human reading of instructions.

```sh
python3 tools/artifacts.py verify
python3 tools/raw_size_decimal94.py --out research/work-items/RE-004-raw-size-decimal-94
python3 -m unittest tests.test_raw_size_decimal94
(cd research/work-items/RE-004-raw-size-decimal-94 && sha256sum -c MANIFEST.sha256)
python3 tools/raw_size_decimal94.py --out <tmp-dir-a>
python3 tools/raw_size_decimal94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Optional human inspection: `objdump -d -M intel --start-address=0x3303d20 --stop-address=0x3303ecc artifacts/node/94/hl-node`. Generated evidence does not depend on disassembler text. `evidence.json` records full FDE bytes and body hashes, file offsets, branches, field links and constants; `vectors.tsv` records the lifted digit model and its inputs.

## Evidence

Addresses are ELF virtual addresses; file offsets and the complete qualified bytes are in `evidence.json`. Each stated extent is an FDE range, not proof of every source-function boundary.

| Site FDE | Field key and source offset | Call | Result |
| --- | --- | --- | --- |
| `0x3277a40..0x3277cd3` | `sz`, object `+0x08` | `0x3277b74` | calls digit writer `0x3303d20` |
| `0x3277ce0..0x3277fc6` | `sz`, object `+0x08` | `0x3277e46` | calls the same digit writer |
| `0x3262d80..0x326300b` | `order_sz`, object `+0x18` | `0x3262e2b` | calls the same digit writer |
| `0x3276830..0x3276b99` | `executed_sz`, object `+0x28` | `0x3276a47` | calls the same digit writer |
| `0x3276ba0..0x3276f09` | `executed_sz`, object `+0x28` | `0x3276db7` | calls the same digit writer |

Each key is loaded from the recorded bytes, followed by its key-writing call and a value load directly into the writer's integer argument. The paths insert a colon and space before that call. The key-writing failure branch enters an error helper, while an earlier nested serializer can return a nonzero result to its caller. Their complete effects are outside this packet. These sites do not perform an intervening multiply, divide or float conversion on the loaded word. The outer functions use key `schedule`, call the corresponding `sz` function, propagate a nonzero result, and later write `executed_sz`. The two nested `sz` routines have different surrounding field layouts, so their overall output is not asserted identical. The outer routines write further fields and call helpers whose internals are outside this packet.

The digit writer has FDE extent `0x3303d20..0x3303ecc`. It builds digits backwards in a 20-byte stack area. Its two-byte table at `0x5853df` contains the ASCII pairs `00` through `99` in order. For `n >= 10000`, the writer obtains `q = (n * 0x346dc5d63886594b) >> 75`, writes the remainder `n - 10000*q` as two table pairs, and continues with `q` while the previous `n` exceeds 99999999. The remaining value takes one of three paths: below 10, one ASCII digit; 10 through 99, one pair; 100 through 9999, a lower pair followed by one digit or pair. No fractional point, sign or rounding operation occurs in this digit slice.

| Digit path | Byte-grounded decision | Consequence |
| --- | --- | --- |
| `0x3303d3b` | unsigned input below 10000 | skip the four-digit loop |
| `0x3303dd3` | previous input above 99999999 | repeat four-digit loop |
| `0x3303dd9`, `0x3303ddf` | remaining value above 99, or at least 10 | choose a pair or single-digit tail |
| `0x3303e6a` | required digit length exceeds spare capacity | call buffer-growth helper then copy |
| `0x3303d6d`, `0x3303dab`, `0x3303de4`, `0x3303e00`, `0x3303e3c`, `0x3303e52` | index arithmetic or bounds failure | enter one of two error helpers |

The generated branch list contains all 13 qualified conditional branches in this digit and append slice, including the tail branches and both error destinations. The copy call and growth helper are observed, but their allocation, panic and unwind effects are not interpreted. The stack-index failures are unreachable in the mathematical digit model: a u64 has at most 20 decimal digits and each loop removes four digits. This is a proof of the model's index bound, not a claim about corrupted caller state.

### Arithmetic argument

For `M = 0x346dc5d63886594b`, the generated evidence reads `10000*M - 2^75 = 432` and checks `(2^64-1)*432 < 2^75`. The multiplication's excess cannot cross the next integer quotient: a nonzero fractional distance to the next multiple of 10000 is at least `1/10000`. Thus the computed quotient equals `floor(n/10000)` over all u64. The other reciprocal reads as 5243, and all 10000 possible remainders satisfy `((r >> 2) * 5243) >> 17 == floor(r/100)`. The 100 table entries are checked byte for byte. By induction over the four-digit chunks and the tail, the lifted digit algorithm produces the usual unsigned decimal digits for every u64, provided the manually interpreted slice corresponds to the qualified instruction bytes and the append helpers behave as assumed.

The generator compares that lift with Python's integer decimal conversion on 1247 deterministic boundary and mixed-bit inputs, with zero mismatches. These are model comparisons, not target executions. The dataset includes 0, both sides of decimal powers, powers of two and their neighbors, the high-bit transition and the maximum u64.

### Inferences

The `sz` and `order_sz` spellings suggest size quantities. The bytes establish the field keys, offsets and raw integer path; they do not establish the economic unit or whether every u64 is reachable. The key-writing and punctuation behavior is consistent with a structured text serializer; this packet does not prove complete JSON output or wire protocol identity.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No build, compiler flags, target execution, raw or normalized binary comparison, or helper/data relocation closure is claimed. The 10 focused Python tests cover the extracted links, reciprocal and digit boundaries; altered digest, instruction, table, key and out-of-range controls are rejected. The generated body bytes and proof are static evidence, not a substitute for target-grounded runtime comparison.

## Results and limitations

Six FDE extents, five field sites, two nested schedule calls, 13 digit-path branches and 100 two-byte table entries are qualified. The pair quotient check covers all 10000 possible remainders; the first reciprocal identity is proved over u64. The 1247 case comparison checks a manual lift, not machine execution. The field names, missing writer helper semantics, input provenance and allocator failures remain open. No full RE-004 progress gate is requested.

Next question: trace non-overlapping producers of these size fields and establish their unit and reachable range before comparing an independent Rust implementation in an authorized harness.
