# RE-004: default million-scale quantity vector in node #94

The selected constructor emits four ordered tag/quantity rows with raw quantities 30,000,000,000,000, 5,000,000,000,000, 2,000,000,000,000 and 500,000,000,000, and the projection converts each to binary64 before dividing by one million; a reconstruction can reproduce the table, order, numeric representation and allocation/error decisions without guessing a decimal scale.

- Component ID: RE-004, quantities/rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed naming lead only.
- Claim status: observation for bytes and decoded selected edges; inference for the semantic name and for the numeric lift under the stated floating-point mode; unresolved items are listed below.
- Scope included and excluded: two FDE extents, their connecting direct call, the constructor's fixed rows, the projection's input/output layout, selected conditional edges and numeric operations. Allocator and vector-growth bodies, callers, serializer, the meaning of each tag, the real input domain, other releases and whole-node equivalence are excluded.

## Reproduce

Run from the repository root, with Python 3 and its standard library. The tool imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, authenticates the target before output, reads ELF bytes, and does not invoke binutils or execute either captured executable.

```sh
python3 tools/artifacts.py verify
python3 tools/default_ntl_vector94.py --out research/work-items/RE-004-default-ntl-vector-94
python3 -m unittest tests.test_default_ntl_vector94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-default-ntl-vector-94 && sha256sum -c MANIFEST.sha256)
```

For a repeatability check, use two initially empty writable directories, with `<first-dir>` and `<second-dir>` replaced by relative paths:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/default_ntl_vector94.py --out <first-dir>
PYTHONHASHSEED=99 TZ=Pacific/Honolulu python3 tools/default_ntl_vector94.py --out <second-dir>
diff -r <first-dir> <second-dir>
```

The generator writes the five evidence files, without timestamps, absolute paths or external commands. The manifest also covers this README. `evidence.json` records full FDE bytes, hashes, ELF virtual and file coordinates, FDE locations, constants and branch edges; `default-rows.tsv`, `branches.tsv`, `numeric-model.tsv` and `count-model.tsv` contain the corresponding results. GNU objdump was used only for human inspection while developing the fixed byte anchors; its output is not a generator input.

## Evidence

All addresses are node #94 ELF virtual addresses before load bias. The FDEs are `[0x2a44500, 0x2a44562)` and `[0x2a10250, 0x2a10584)`. Their end addresses come from `.eh_frame`; the direct call and return paths below add control-flow evidence, but an FDE alone does not establish a source-level function boundary. The generator rejects changed function bodies, changed branch encodings, altered data and a mismatched target digest.

### Constructor and result

The unique `R_X86_64_RELATIVE` relocation for slot `0x5774f98` names the constructor; this binds a file-backed indirect entry without claiming an upstream caller. The constructor initializes an input object with a nonzero flag, a nonempty one-element optional range, tag 1 and raw word 500,000,000,000. Two RIP-relative operands delimit three 16-byte records at `[0x421bb8, 0x421be8)`, and a direct call passes that object to the projection. In each record the first byte is copied as a tag and the u64 at offset 8 is converted; the seven intervening bytes are not claimed as meaningful fields. A second, byte-identical 48-byte data copy exists at `0x5995d8`.

| Input order | Tag | Raw u64 | Binary64 result |
| ---: | ---: | ---: | ---: |
| 0 | 25 | 30,000,000,000,000 | 30,000,000 |
| 1 | 20 | 5,000,000,000,000 | 5,000,000 |
| 2 | 10 | 2,000,000,000,000 | 2,000,000 |
| 3 | 1 | 500,000,000,000 | 500,000 |

For a successful allocation the projection writes these records in this order, including the last optional record, into 16-byte output elements: byte `+0` is the tag and the binary64 result is at `+8`. The returned three-word container stores capacity, allocation pointer and length. The constructor's fixed path requests four elements, or 64 bytes. Exact result bits are in `default-rows.tsv`. Each fixed input is below 2^53 and is an exact multiple of one million, so both the input conversion and its division are exact on this path.

### Projection decisions and failure edges

For a well-formed readable base span, `n` is `(base_end - base_start) >> 4` when the base pointer is nonzero, otherwise zero. If the flag is nonzero, the other range contributes `optional_end - optional_start` to the requested capacity; otherwise it contributes zero. The caller is responsible for valid ranges, readable records, and a live, nonaliasing output allocation. The table below summarizes the qualified instruction blocks, not executions of the node:

| Condition | Observed or modeled consequence |
| --- | --- |
| Base pointer is zero | The base count is zero and the base loop is bypassed. |
| Optional flag is zero | The optional range contributes no capacity and no final record. |
| Base count plus enabled optional span carries out of u64 | The count-overflow edge calls an external error routine; no successful return is established on that edge. |
| Capacity times 16 overflows or exceeds `0x7ffffffffffffff8` | The allocation-layout failure edge is taken before allocation. |
| Allocation size is zero | A non-null aligned empty-vector pointer and zero capacity are selected. |
| Nonzero allocation returns null | The allocation-error edge calls an external routine. |
| Recomputed input count exceeds initial capacity | A vector-growth helper is called; its body and possible effects are not analyzed. With unchanged, valid, nonaliased input fields, the two count computations agree. |
| Base records exist | Pairs are copied through the unrolled loop, followed by an odd-record tail when needed. |
| Flag is nonzero and the optional range is nonempty | Exactly one additional record is appended from the inline tag and raw word. |
| An unwind passes through cleanup | A nonzero capacity causes the allocation to be passed to an external free routine before unwind resumes. |

`branches.tsv` gives the 20 selected conditional branch destinations and fallthroughs read directly from the machine bytes, plus the manually lifted choices for the successful default path (17 reached and 3 unreached). `count-model.tsv` has 75 synthetic count cases, including null, empty, even and odd base counts, the optional tail, count overflow and the allocation-size boundary. These are predictions from the manually lifted decisions, not target execution. They do not establish that malformed ranges or optional spans greater than one can occur in a real caller.

### Binary64 conversion

The vector loop and both scalar tails use the packed low/high u32 conversion sequence and the same file-backed 1,000,000.0 binary64 divisor. For any u64 input, the two integer halves and the shifted high half are exactly representable as binary64. Under round-to-nearest, ties-to-even, adding those halves performs one rounding to binary64; dividing that rounded result by the divisor performs a second rounding. Thus the mathematical expression is `RN64(RN64(x) / 1000000)`, not necessarily `RN64(x / 1000000)`.

`numeric-model.tsv` compares two independent *models*: an integer-rational nearest-even implementation and a lift of the actual unpack/subtract/add/divide constants and operations using host binary64. They agree on 544 deterministic edge inputs; 57 of these differ from a single rounding of the exact rational quotient. For example, input 9,007,199,254,740,993 gives two-stage bits `0x4200c6f7a0b5ed8d`, while one rounding gives `0x4200c6f7a0b5ed8e`. This is a general projection input, not one of the four fixed constructor inputs. The argument about the two halves covers the complete u64 range under the stated mode; the sample does not measure the target's runtime floating-point environment.

### Inference and unresolved identity

The pinned reference names a `maxMarketOrderNtls` request, which is a possible interpretation of this kind of tag/amount vector. The present packet does not prove that request reaches this constructor, that the tags denote leverage, or that the quantities have a particular currency unit. Those remain naming leads. The numeric scale, row order, four input words and fixed-path outputs above are observations or deductions from the selected bytes.

## Implementation and comparison

Independent Rust: not yet implemented. Cargo lock, compiler/linker provenance, repeated builds and binary comparisons: not yet implemented/measured. There is no normalization mask or claim about helper, relocation, vtable or whole-ELF closure. The arithmetic lift and the independent rational oracle are written in Python for static evidence, not offered as recovered Rust.

The focused suite has 15 tests and no skips. It checks the two FDE extents and default rows, exact outputs, rounding ties, representative binary64 boundaries, count/allocation edges, all listed branch targets, and rejects a wrong target hash, a changed FDE extent, changed or duplicate relocation slots, altered branch/instruction/pointer/data/divisor/SIMD bytes, out-of-range addresses and NOBITS reads. It additionally checks that changing the divisor changes the numeric lift. The model assumes a round-to-nearest host when comparing the lifted float operations.

## Results and limitations

Five deterministic evidence files were produced. The 544 numeric comparisons had zero lift/model disagreements, and the 75 count cases are model predictions. No target executable was run, no Rust code or end-to-end externally visible request behavior was tested, and no progress gate is requested. The branch table covers the 20 explicitly enumerated conditional edges; it is not a whole-program CFG, a whole-function instruction-coverage result, or proof that an external failure helper returns or unwinds in a particular way.

Next question: bind the actual request and serializer to the four-row constructor without reanalyzing an already-owned function, and establish whether a real caller can supply a variable or malformed optional range.
