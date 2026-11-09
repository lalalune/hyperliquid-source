# RE-009: node #115 Vec<u8> serializer leaves (grow, decimal, JSON escape/entry/pretty field/struct, rmp unsigned, record array)

With this packet, the byte-level writers that every state-export serializer in node #115 sits on can be rebuilt as
pure Python (and from there as Rust) functions: the amortised grow of the output byte vector (`0x4787e90` with its
reallocator `0x4787da0`), the two u64 decimal formatters (`0x4779320`, `0x4301950`), the JSON string-escape writer
(`0x4778320`), the compact map entry (`0x4777ad0`), the pretty-printed struct field (`0x4777cc0`) with its one-field
struct driver (`0x4783f20`, whose only field is the 27-byte key `bucket_limit_mult_threshold`), the rmp unsigned-integer
writer (`0x47789c0`, fixint / `0xcc` / `0xcd` / `0xce` / `0xcf`, with its io-error result) and the JSON array-of-records
writer (`0x4776de0`). Every branch, capacity decision, growth call, memcpy and failure result of those nine bodies
(plus the reallocator) is reproduced by one reconstruction and checked against the real machine code in 13,000
cases (0 mismatches); all 47 negative controls are detected.

- Component ID: `abci` (work item RE-009, storage / state-export serializers; the callers are the router bodies of the earlier RE-009 packets)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main (no source; binary-only; the tool is independent work)
- Claim status: reconstruction of the observable behaviour of the listed bodies, validated against the evaluated #115 machine code. The callees stubbed by the shared environment (heap allocator, memcpy, f64 text, element writer `0x4781f10`, panic entries) are described by their calling convention only; their internals are not claimed. Role names (state-export writer, compact/pretty serializer, "record array") are inferences.
- Scope: included nine complete FDEs plus the reallocator (`0x4787e90` 142 B, `0x4787da0` 233 B, `0x4779320` 322 B, `0x4301950` 322 B, `0x4778320` 552 B, `0x4777ad0` 492 B, `0x4777cc0` 1241 B, `0x4783f20` 518 B, `0x47789c0` 1966 B, `0x4776de0` 2006 B = 7,794 code bytes, 1,944 instructions). Excluded: the internals of the element writer `0x4781f10` (811 B) and the f64 formatter behind `.got 0x64e13d0` (target `0x5d0e4c0`), the allocator entries, the panic entries, and the drivers above these writers (`0x4773b90`, `0x4774080`, `0x4771750`, see `callers.tsv`).

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus the shared `tools/elf_index.py`, `tools/fde_extents.py` and the repository's concrete x86-64 evaluator `tools/re16_state_compose115.py` (imported, not copied). No external program is called and the binary is never executed.

```
python3 tools/re009_vec_writer_serializers_115.py --out research/work-items/RE-009-vec-writer-serializers-115
python3 -m unittest tests.test_re009_vec_writer_serializers_115
```

The tool checks the input SHA-256 first. It writes `callers.tsv`, `cases.tsv`, `constants.json`, `instructions.tsv`, `measure.json`, `negative-controls.tsv`, `outcome-classes.tsv` and `summary.json`; `MANIFEST.sha256` lists them. Regeneration takes about 35 s and about 430 MB, and is byte-identical across runs with different `PYTHONHASHSEED` and `TZ`.

## Evidence

All coordinates are virtual addresses in node #115 (`.text` VA = file offset + 0x1000). Every number in the evidence files comes from ELF bytes read with `struct`: the `.rela.dyn` entries, the FDE extents from `.eh_frame`, the escape and hex tables, the pair tables, the key constant and the code bytes. Instruction forms come from fixed byte patterns decoded by the shared evaluator, extended in the tool by two encodings it lacks (`66 c7` with a 16-bit immediate, `66 0f d6` movq store).

- **Vec<u8> layout.** Every writer takes the vector as capacity `+0x0`, pointer `+0x8`, length `+0x10`. A write of `n` bytes checks `cap - len >= n` (single bytes: `cap == len`); otherwise it calls the grow `0x4787e90(vec, len, n, align = 1, elem = 1)`.
- **Grow `0x4787e90` / `0x4787da0`.** `need = len + n` (carry: capacity-overflow panic via `.got 0x64df498` with `rdi = 0`); `new = max(2 * cap, need)`, then at least 8 for one-byte elements (4 for elements up to 1024 bytes, else 1); the reallocator multiplies by the element size (overflow or more than `2^63 - align` bytes is the same panic), uses plain `realloc/malloc` (`.got 0x64df588 / 0x64df480`) when `align < 17 && align <= bytes` or `align` is odd, otherwise the aligned entries (`0x64df580 / 0x64df590`, third argument = trailing-zero count of the alignment), returns the alignment itself for a zero-byte first allocation, and passes `(align, bytes)` to the allocation-failure handler when the allocator returns null. The rmp writer inlines the same arithmetic (`max(2 * cap, need) >= 9 ? that : 8`) and reports failures as a result instead of panicking.
- **Decimal formatters.** `0x4779320` and `0x4301950` are the same body (different pair-table addresses `0x7e17d6` and `0x7c9625`, both equal to `"0001...99"` in the tool's check). They fill a 20-byte scratch from the end, four digits per step (divide by 10^4 with the multiplier `0x346dc5d63886594b`, then two table pairs) and return `(buffer + start, length)`. `0x4301950` has 59 `e8` call sites in 53 other functions (`callers.tsv`); `0x4779320` is used only by `0x4776de0`, `0x4777ad0` and `0x4777cc0`.
- **JSON escape.** The escape table behind `.got 0x64e13d8` (target `0x946dcc`) holds `0x75` ('u') for all control bytes except `\b \t \n \f \r` (`b t n f r`) and `\"`, `\\` map to themselves; the hex digits behind `.got 0x64e13e0` are lowercase. Clean runs are flushed with one capacity check and one memcpy; escapes are written as `\uXXXX` (needs 6) or `\c` (needs 2). `0x4777cc0` carries an inlined copy of this loop; `0x4778320` is the stand-alone body.
- **Compact entry `0x4777ad0`.** `(state, ser, key, &u64)`: a state byte of 1 means "first" (no comma); it is set to 2 before the key; it writes `,"key":digits`. A set error flag (`[rdi] == 1`) takes the `unreachable` panic (`.got 0x64df730`, message address `0x7e178d`, length `0x28`, text "internal error: entered unreachable code").
- **Pretty field `0x4777cc0` and struct `0x4783f20`.** The field writes `\n` (first) or `,\n`, then `depth` copies of the indent string, then `"key": digits`, and sets the has-value byte (`+0x20`). The struct driver increments the depth (an all-ones depth takes the overflow panic `.got 0x64df520`), clears the has-value byte, writes `{`, writes the single field with the 27-byte key at `0x7e1c4f` (`bucket_limit_mult_threshold`), decrements the depth and, because a field was written, writes `\n` + indent + `}`.
- **rmp unsigned `0x47789c0`.** `v < 0x80` is a positive fixint (`out +8 = 0, out +9 = v, out +0 = 2`); `v < 0x100` is `0xcc v`; `v < 0x10000` is `0xcd` + big-endian 16; `v < 2^32` is `0xce` + big-endian 32; else `0xcf` + big-endian 64. The result is `out +0 = 2` and the marker at `out +8` on success; on an allocation failure `out +0` is 0 (marker write failed) or 1 (payload write failed) and `out +8 = 0x2600000003`. The marker byte stays written (length incremented) when the payload cannot be reserved.
- **Record array `0x4776de0`.** `[` then, per record, `[` element (`0x4781f10`, stubbed) `,u64,u64,f64]` separated by `,`, then `]`; an empty slice gives `[]`; a non-zero return of the element writer is propagated. The f64 field is `null` when `|x| > 0x7fefffffffffffff` (inf/nan), otherwise the text produced by `.got 0x64e13d0`.
- **Callers.** `callers.tsv` lists every `e8 rel32` pattern aimed at one of the ten starts, with the FDE that contains it. The grow has 137 sites in 30 bodies; `0x4783f20` and `0x47789c0` are called only by `0x4773b90`; `0x4776de0` by `0x4774080`; `0x4777ad0` by `0x4771750`; `0x4777cc0` only by `0x4783f20`.
- **Coverage.** Executed instructions per body are in `summary.json` / `instructions.tsv`: grow 41/41, reallocator 73/74 (the zero-byte first allocation `mov rax,r15` at `0x4787e67`, which needs `new_cap * elem == 0`), entry 131/131, field 306/307 and escape 139/140 and array 485/486 (one alignment `nop` each), decimal 77/81 (the four others are the overflow panics after `jo` at `0x4779448..` / `0x4301a78..`), struct 128/131 (the has-value-clear branch `0x4784067`, which the field always sets, and the depth-zero panic at `0x4784119`), rmp 376/472. The 96 unexecuted rmp instructions are the "grow again after the inline grow" fallbacks, which need `new_cap == len` after a successful doubling and are unreachable.

## Implementation and comparison

Independent Python reconstruction in `tools/re009_vec_writer_serializers_115.py` (`Env`, `model_*`). Rust is not yet implemented. The shared `Env` (heap with deterministic addresses, allocator failure injection, memcpy log including the copied bytes, f64 text, element writer, `Panic`) is used both by the model and by the stubs the real code calls, so the capacity, pointer, bytes, allocation/memcpy log, panic arguments and return registers must all be equal. The evaluator runs the unmodified bytes of the ten FDEs; callee-saved registers and the stack pointer are checked after every normal return.

- **Cases (13,000).** Per body: grow 1,700 (align 1..4096, element 0..4096, huge fake capacities, `len` different from the header, allocator failure at call 0..3); decimal 900 + 900 (every digit count, powers of ten, `2^64 - 1`); escape 1,700 (random, control-heavy and printable keys of length 0..40); entry 1,500; field 1,500 (indent length 0..4, depth 0..4, error flag); struct 900 (depth 0..4 and all-ones); rmp 2,400 (every marker and boundary, vectors with room `need - 1 / need / need + 1`, failures, near-`2^64` fake capacities); array 1,500 (0..4 records, finite / infinite / NaN / negative zero floats, element-writer failure). Outcome classes are in `outcome-classes.tsv` (for example 77 + 23 rmp io-error results, 29 depth-overflow panics, 514 grow panics).
- **Negative controls (47).** 20 wrong reconstructions (no doubling, minimum 4, ignored alignment, dropped decimal digit, upper-case hex, `/` escaped, comma always, stuck state, swapped separators, one indent, tight colon, depth kept, fixint limit `0xff`, `0xce` as `0xcd`, swapped error tag, little-endian payload, inf as finite, missing record comma); 24 corrupted code bytes (condition inversions inside each body, three per body, each detected); 3 input controls (flipped `.text` byte rejected by the digest check, address past `.text`, read below the first file-backed section).
- **Tests.** `tests/test_re009_vec_writer_serializers_115.py` (16 tests): regenerated evidence equals the packet byte for byte, manifest, model vs machine code for every body, grow policy and failure results, decimal formatters, every rmp marker, rmp io-error results, escape table and output, pretty struct text, array with a non-finite float, mutants, corrupted bytes, input controls, constants, decoder extensions.

## Results and limitations

`measure.json`: cases 13,000, negative controls 47, detected 47. Chain hash over all case results is in `summary.json`; `cases.tsv` lists every fourth case (3,250 rows; the chain hash covers all 13,000) with its parameters, outcome and result digest.

- The evaluator is a concrete model: only the paths reached by the 13,000 cases are proven. The unexecuted instructions listed above are the landing pads after the non-returning overflow panics and the unreachable rmp fallbacks.
- The element writer `0x4781f10`, the f64 text of `.got 0x64e13d0`, the allocator entries and the panic entries are shared stubs. The f64 text of the stub is Python's `repr`; the real formatter's output is not claimed.
- Unclaimed: which exported struct the `bucket_limit_mult_threshold` field belongs to, and who consumes the record array. No component gate is requested.

Next question: the drivers `0x4773b90` (already reconstructed with these writers stubbed), `0x4774080` (array caller, 555 B) and `0x4771750` (entry caller, 326 B), and the element writer `0x4781f10` with its helper `0x4772bc0`.
