# RE-004: reconstruct the node #115 BOLE reserve reply 0x38e64b0 (read address 0x…0812): gas, token search, eight reply words and the supply rate, 9,473 compared cases and 212 negative controls

This packet answers the next question of `RE-004-bole-rate-curve-115`: what `0x38e64b0` does with the rate word, the two utilization results and the token tree. It is the callback stored for address `0x0000000000000000000000000000000000000812` in a table of address and callback pairs. It charges gas, parses one token index, finds the token record in an ordered store, and returns eight 32 byte big-endian words. Word 1 is where the supply rate is formed: `rate × utilization × (1 − reserve / 1e14)` in f64. The packet lets a reconstruction write the whole body as a rule list, and adds a Rust crate for the arithmetic that passes 423 vectors read from runs of the target bytes.

- Component ID: RE-004 (quantities and rounding), component `assets`; BOLE token arithmetic. Touches `evm` only as the owner of the table.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace `a8616af94`. No reference tree text was read or used. The merged packet `RE-004-bole-rate-curve-115` supplies the rule list of the three callees (`tools/bole_rate115.py`, imported, not copied).
- Claim status: observation for everything in Evidence (ELF bytes, relocations, and an interpreter that reads the bytes); inference where marked; unresolved where marked.
- Scope included and excluded: included is the body `0x38e64b0..0x38e6c70` (1,984 bytes, 393 instructions), interpreted whole, with the real bytes of `0x36a0b30`, `0x36a08b0` and `0x36a09f0` under it. Stubbed at the edge, each checking its arguments: the input parser `0x3897200`, the ring search `0x4556410`, the two message builders `0x46de430` and `0x3d4eb60`, three drops, the allocator slots, the 128 bit divide and the bytes constructor `0x161cc70`. Excluded: what those callees compute, the unwind landing pads `0x38e6c70..0x38e6d3f` (207 bytes, never interpreted), who registers or walks the table, and who writes the store and the reserve word. No component gate is requested.

## Reproduce

From the repository root with Python 3 (3.11.5 here, macOS arm64; the tool is pure standard library and only reads the ELF) and Rust 1.95.0. No network, no key, and the binary is never executed.

```sh
python3 tools/bole_reserve_reply115.py --out research/work-items/RE-004-bole-reserve-reply-115
python3 -m unittest tests.test_bole_reserve_reply115
(cd src/node115-bole-reserve-reply && cargo test && cargo clippy --all-targets -- -D warnings)
(cd research/work-items/RE-004-bole-reserve-reply-115 && shasum -a 256 -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first, reads the ELF through `tools/x86_115.py` (shared interpreter over `tools/elf_index.py` and `tools/fde_extents.py`), calls no external program and parses no objdump or readelf output. It took 5 min 5 s here (about 80 s for the vectors, the rest for byte edits and wrong-reading switches); the tests took about 2 min 20 s. Two runs give byte-equal files: the regeneration test compares a fresh run with the committed files.

Generated files: `evidence.json`, `measure.json`, `function-rows.tsv`, `table-entries.tsv`, `slots.tsv`, `call-sites.tsv`, `constants.tsv`, `reciprocals.tsv`, `reply-samples.tsv`, `outcomes.tsv`, `vector-outcomes.tsv`, `model-variants.tsv`, `structural-controls.tsv`, `mutations.tsv`, `unreached-rows.tsv`, `rust-vectors.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses of the ELF; in `.text` and `.rodata` they equal file offsets. The function start and end `0x38e64b0..0x38e6d3f` (2,191 bytes) are one FDE (`tools/fde_extents.py`). The decoder lands exactly on `0x38e6c70`, the first landing pad.

### Where the body is referred to

`table-entries.tsv`: `.data.rel.ro` holds 32 byte entries of 20 address bytes, 4 zero bytes and a `R_X86_64_RELATIVE` callback pointer.

| Slot | Address bytes | Callback |
| --- | --- | --- |
| `0x646e738` | `…0811` | `0x38e5d00` |
| `0x646e758` | `…0812` | `0x38e64b0` |
| `0x646e778` | `…0814` | `0x38e6d40` |

`.text` holds no `call` or `jmp` with a 32 bit displacement to `0x38e64b0`, and the table slot is the only relative relocation that holds it (`test_only_the_table_slot_refers_to_the_body`). `slots.tsv` resolves the seven GOT slots the body calls through, each by its relative relocation.

### Arguments and result

`rdi` = result (5 words), `rsi` = context, `rdx` = input pointer, `rcx` = input length, `r8` = gas limit.

| Read | Role in the code |
| --- | --- |
| `[[rsi+0x10]+0x38]` | count: a token index at or above it is refused |
| `[rsi+0x48]` = S | state that holds the store and the reserve word |
| `S+0x58` | store tag: `0x8000000000000000` is the B-tree form, any other word is the ring capacity |
| `S+0x60`, `S+0x68`, `S+0x70` | tree root and height; or ring buffer, head and length |
| `S+0x78` | reserve word (u64, scale 1e14) |

Result forms (word 0 is zero for every refusal, and the non-null first word of the bytes value for a reply):

| Form | Words |
| --- | --- |
| reply | `[bytes word 0, pointer, length, bytes word 3, gas charged]` |
| out of gas, or input longer than 2,000 | `[0, 0x8000000000000001]` |
| message | `[0, capacity, pointer, length]` of a text |

### Rule list (each line is checked by the cases below)

```
if len > 2000: out of gas
first = 1000 + 33 * len                      ; if first > limit: out of gas (nothing else is called)
parse(input, len) -> tag, token              ; tag != 0x0c: drop the parse result, text "Invalid input" (13 bytes)
if token >= count: message(code 0xfa, token)
find token:
  tree: root null, or key absent             -> message(code 0xf1, 0x00)   (builder 0x46de430, then a drop)
  ring: first search answers non-zero        -> message(code 0xf1, 0x00)
        second search bit 0 set, or index >= length -> message(code 0xf1, 0x0c)   (builder slot 0x64e9570, no drop)
        record = buffer + ((head + index) wrapped once by capacity) * 0xb8 + 8
qb = divide(a * ia, 1e14)                    ; a, ia = record +0x40, +0x58
qs = divide(b * ib, 1e14)                    ; b, ib = record +0x60, +0x78
rate = 0x36a0b30(record)                     ; rate / 1e10
uw   = 0x36a08b0(record)                     ; utilization / 1e10; a refusal -> message(code 0xf1, 0x0c), f64 body not called
uf   = 0x36a09f0(record)                     ; utilization as f64 / 1e14; a refusal -> message(code 0xf1, 0x0c)
y    = (f64(reserve) / -1e14 + 1.0) * (f64(i32(low 32 bits of rate)) * uf)
supply = 0 if y is not finite; 0 if y <= 0; 2^64-1 if y >= 2^64; else trunc(y)
words = [ rate, supply, record+0x18, uw, record+0x10,
          (record+0x08) / 1e10 if the dword at record+0 is 1 else 0,
          0 if high(b * ib) > 1e14 - 1 else low(qs),
          0 if high(a * ia) > 1e14 - 1 else low(qb) ]
reply = each word as 24 zero bytes and 8 big-endian bytes (0x100 bytes; allocations of 0x100 and 0x20, the 0x20 box is freed at once)
total = saturating(first + saturating(33 * reply length))
if total > limit: drop the reply, out of gas ; else reply with total
```

Points a reconstruction would get wrong without the bytes:

- **Word 7 floors, the ratio ceils.** The borrowed total in the reply is `floor(a·ia / 1e14)`; the utilization inside the callees uses the ceiling of the same product. `a = 3`, `ia = 1e14 + 1`, `b = 8` gives word 7 = 3 and word 3 = 5000 (4/8), not 3750.
- **The rate enters the supply rate through a 32 bit signed conversion** (`cvtsi2sdl 0x80(%rsp)` at `0x38e687b`). The largest word `0x36a0b30` can return is `(2^64−1)/1e10 = 1,844,674,407`, below 2^31, so nothing is lost on real input; cases with an injected rate word show the low-half and sign reading (`2^32 + 5` gives 5, `2^31` gives 0).
- **The reserve factor is `reserve / −1e14 + 1.0`** (pool values `0x4599c8` = −1e14, `0x4592b0` = 1.0; `constants.tsv`), with the u64 converted in two lanes. A reserve word above 1e14 makes the factor negative and the word 0.
- **A non-finite product gives 0, not the largest word** (`0x38e68c3..0x38e68e5`), unlike a plain saturating cast.
- **The two ring answers are read differently**: the first as a whole word (`test rax, rax`), the second by bit 0 (`test al, 1`). Answer 2 refuses on the first call and is accepted on the second.
- **The first charge uses 33 a byte, and the reply is charged 33 a byte again**, both on the byte length. A 32 byte input and the 256 byte reply cost 1000 + 1056 + 8448 = 10,504.
- **The second tree walk cannot miss.** The body walks the tree twice (first to test for the key, then to take the value). Its refusal `0xf1/0x0c` after the second search is reached only in the ring form.

### Block walk (observation; raw rows in `function-rows.tsv`)

| Range | What the bytes do |
| --- | --- |
| `0x38e64b0..0x38e64e5` | frame `0x128`; `len > 0x7d0` refuses; `r13 = len + (len << 5) + 0x3e8`; `r13 > r8` refuses |
| `0x38e64e7..0x38e6510` | refusal exit: `[rbx+8] = 0x8000000000000001`, `[rbx] = 0`, return `rbx` |
| `0x38e6511..0x38e6530` | `r15 = [rsi+0x10]`, `rbp = [rsi+0x48]`; parser `0x3897200(rsp+0x10, input, len)`; tag byte against `0x0c` |
| `0x38e6536..0x38e653f` | `r12 = token`; `r12 >= [r15+0x38]` goes to code `0xfa` |
| `0x38e6545..0x38e65d5` | store tag against `0x8000000000000000`; first tree walk: node length `+0x7f2`, keys from `+0x798`, edges from `+0x7f8`, compare by `seta`/`sbb` |
| `0x38e65d7..0x38e6694` | refused parse: the 0x58 byte result is copied and dropped (`0x38f9750`), 13 bytes allocated, the two overlapping 8 byte stores write `Invalid input` |
| `0x38e6699..0x38e6718` | codes `0xfa` + token and `0xf1`/`0x00` through `0x46de430`, then drop `0x3d57b80` |
| `0x38e66bb..0x38e66cc`, `0x38e6724..0x38e6733`, `0x38e6910..0x38e694a` | ring form: search `0x4556410(S+0x58, &token)` twice; index against `[S+0x70]`; `+ [S+0x68]`, minus capacity when not below it; `* 0xb8 + 8` |
| `0x38e6739..0x38e67c3` | second tree walk; values are `0xb0` apart from the node start |
| `0x38e67c3..0x38e6829` | the two products and the two divides by `0x5af3107a4000` through slot `0x64dfaf8` |
| `0x38e682d..0x38e6875` | `0x36a0b30`, `0x36a08b0`, slot `0x64e8d50` (`0x36a09f0`); tag byte 1 of either Result goes to `0xf1`/`0x0c` |
| `0x38e687b..0x38e68ba` | `cvtsi2sdl`, `mulsd` by the f64 utilization; reserve word to f64 in two lanes; `divsd` −1e14, `addsd` 1.0, `mulsd` |
| `0x38e68be..0x38e69d7` | finite test on the absolute bits; clamp; the u64 cast (`cvttsd2si` twice, 2^63 bias, tests against 0 and the largest f64 below 2^64) |
| `0x38e69db..0x38e6a5a` | `cmpl $1, (record)`; multiply by `0xdbe6fecebdedd5bf`, shift 33 of the high half (÷ 1e10, `reciprocals.tsv`); the two 128 bit guards by `cmp`/`sbb` against `(1e14−1):2^64−1`; `bswap` of every word |
| `0x38e6a5f..0x38e6b8a` | allocate `0x100` and `0x20`; write eight words at `+0x18, +0x38, … +0xf8` with zeros before each; free the `0x20` box |
| `0x38e6b90..0x38e6c30` | bytes constructor through slot `0x64df948`; `length * 0x21` with `jo`; add with carry to the largest word; over the limit drops the bytes through `[word 0 + 0x20]`; else copy four words and the charge |
| `0x38e6c35..0x38e6c6e` | saturation arm, three allocation-failure calls (`0x64df498`), `ud2` |

`unreached-rows.tsv`: every body row except the final `ud2` at `0x38e6c6e` is reached, all of them with the real callees.

### Inferences (not observations)

- Role names: "count" is the number of tokens, the store is the BOLE token map, the reserve word is the reserve factor, word 1 is the supply rate (`supplyYearlyRate` in the #94 reading quoted by the rate packet), word 0 the borrow rate, word 3 the utilization, words 6 and 7 the supplied and borrowed totals. Words 2, 4 and 5 are named only by their record offsets here (`+0x18`, `+0x10`, optional `+0x08` ÷ 1e10); the merged rate packet's fixture calls them `bal`, `px` and `ltv`, which is also inference.
- The B-tree and ring forms look like one ordered-map type with two layouts (a `BTreeMap` and a sorted ring buffer searched by `0x4556410`); which is live on chain is not established.
- The table is read as a table of read precompiles from the address bytes and the gas shape. Its dispatcher is not traced here.
- The slot targets `0x6355830`, `0x635de30`, `0x141e264` are read as allocate, free and allocation-failure from their arguments; `0x161cc70` as a bytes-from-vector constructor from the four words it must return for the body to continue, with a drop at `+0x20` of its first word.

## Implementation and comparison

**Rule list.** `spec` in `tools/bole_reserve_reply115.py`, written from the block walk and sharing no code with the interpreter. For the three callees it calls the merged rule list of `tools/bole_rate115.py`. Each case is compared on: every heap byte after the run (result words, reply bytes, text, and everything that must not change), the ordered stub requests with their arguments, the ordered 128 bit divide requests (the body's two and every one inside the real callees), and whether the run ended in the allocation-failure call.

**Interpreter.** `tools/x86_115.py`, unchanged. The tool adds two forms in a subclass, because this body uses them and the shared module refuses them: the flags of the one-operand `mul` (read by `jo` at `0x38e6bd3`) and `cvtsi2sd` with a 32 bit source (`0x38e687b`). The shared decoder reads `unpcklps` at `0x38e688f` as `punpckldq`, which interleaves the same lanes.

**Rust.** `src/node115-bole-reserve-reply` (independently authored, `no_std`, no dependencies, `Cargo.lock` committed, Rust 1.95.0): `first_charge`, `whole_charge`, `utilization`, `rate`, `supply_rate`, `reply_words`, `reply_bytes`. Its test reads `rust-vectors.tsv`: 423 found-token inputs with the reply words the target bytes produced (326 replies, 97 utilization refusals), and passes all of them; a second test changes inputs and requires a different answer. No object-code comparison was made: the crate is checked on behaviour, not on bytes, and no byte window is registered.

| Group | Cases |
| --- | --- |
| Named cases, real callees (lengths and gas edges, parse refusals, count edges, tree shapes of height 0 to 2, ring layouts, the 71 records of the rate packet, reserve words, optional word, allocation failures, reported reply lengths) | 350 |
| Named cases, injected callee answers (rate words around 2^31 and 2^32, f64 edges including NaN, infinities and the 2^63 and 2^64 cast edges, refusal tags, products at the guard) | 123 |
| Pseudo-random vectors (`lcg` seed `0x5eed0812`), of which 2,998 with injected callee answers | 9,000 |
| Total compared | 9,473 |
| Mismatches | 0 |

| Negative control | Count | Detected |
| --- | --- | --- |
| Wrong readings of the rule list (`model-variants.tsv`: 32 a byte, no base charge, limit 2001, reply not charged, wrapping charge, `<=` count, any parse tag, swapped miss codes, the two ring flag readings, no length test, no wrap, 64 bit or unsigned rate, reserve scale 1e10, plus sign, no reserve, word utilization in the product, rounding cast, NaN to the largest word, wrapping below zero and above 2^64, raw optional word, always or any tag, swapped `+0x10`/`+0x18`, swapped totals, ceiled borrowed total, no guard, `>=` guard, little-endian, word order, utilization refusal ignored, box freed first, 12 byte text) | 35 | 35 |
| Structural (`structural-controls.tsv`: changed digest, five wrong function starts, neighbour table slot, wrong utilization slot, another reserve word, one flipped reply bit, one flipped store bit) | 11 | 11 |
| Byte edits of reached rows (`mutations.tsv`: condition flips, immediate bit, displacement bit) | 174 | 166 killed (2 need injected callee answers) |
| Total counted | 212 | 212 |

Eight byte edits survive and are not counted: each is listed in `mutations.tsv` with the reason it cannot change the result (the overlapped text byte, the height counter of the second walk twice, bit 0 of the sign mask, the two clamp branches that the cast repeats, the shift whose lost bit is always zero in an f64 that large, and the saturated product that carries either way).

Tests: `tests/test_bole_reserve_reply115.py`, 20 tests in three groups (comparison with the rule list, properties of the bytes stated without it, and the committed evidence regenerated).

## Results and limitations

- `measure.json`: cases 9473, negative_controls 212, negative_detected 212. Rust: 5 tests, 423 vectors, 0 mismatches; clippy clean with `-D warnings`.
- Limits:
  - The parser, the ring search, both message builders, the drops, the allocator and the bytes constructor are stubs. The packet proves what the body does with their answers and which arguments it gives them, not what they compute. In particular the texts of the `0xfa` and `0xf1` messages, and which input encodings the parser accepts as a token index, are not established.
  - Injected answers reach states real callees cannot (a rate word above 2^31, a non-finite utilization, a guard that fires after a successful utilization). The rows are real; the states are not claimed to occur.
  - The 207 landing-pad bytes are not interpreted and not claimed.
  - Trees are generated with height 0 to 2 and at most 27 keys; the ring with at most 27 entries. Unsorted stores are outside the model.
  - Interpreted on macOS arm64 only. The tool has no platform-dependent step, but Linux and hosted CI results are not claimed.
  - `research/components.json` is not edited, so the new crate is not listed under a component. No progress gate is requested and no completion number changes.

Next question: the parser `0x3897200` (which input bytes become tag `0x0c` and a token index, and what its other tags are) and the two message builders, so that the refusal texts of address `0x…0812` can be written; then the neighbour callbacks `0x38e5d00` (`0x…0811`) and `0x38e6d40` (`0x…0814`).
