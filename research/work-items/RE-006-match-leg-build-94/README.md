# RE-006: matching-leg record construction and error cleanup on node #94

This packet establishes how the two selected matching legs obtain their fields and distinguishes a missing auxiliary value from an auxiliary failure that produces a present zero, allowing a reconstruction to preserve that decision and the error cleanup path.

- Component ID: `orderbook` (RE-006, matching).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed `references/can1357-hl` lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: machine bytes, offsets, control-flow targets, and relocation are observations; the leg, user and option names and the truth table are inferences from those observations; unknowns are below.
- Scope included and excluded: the selected builder, its two observed selector call sites, the error cleanup FDE and its bounded relative jump tables. The surrounding match loop and bodies of the callback, optional auxiliary, and further cleanup callees are outside this packet. No captured binary is executed.

## Reproduce

Use the repository root, the authenticated artifact and Python's standard library. Author environment: Linux x86-64, Python 3.12.3, GNU objdump 2.42 for human inspection only. The collector uses the repository's `tools/elf_index.py` and `tools/fde_extents.py`; neither the collector nor its tests invokes a disassembler or another program. Output does not include time, locale, host paths, or disassembler text.

```sh
python3 tools/artifacts.py verify
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_match_leg94.py --out work/match-leg-a
PYTHONHASHSEED=431 TZ=Pacific/Honolulu python3 tools/book_match_leg94.py --out work/match-leg-b
diff -r work/match-leg-a work/match-leg-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 work/match-leg-a research/work-items/RE-006-match-leg-build-94
python3 -m unittest tests.test_book_match_leg94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-match-leg-build-94 && sha256sum -c MANIFEST.sha256)
```

Human instruction-boundary inspection, not an input to any generated file:

```sh
objdump -d --start-address=0x49e4210 --stop-address=0x49e4449 artifacts/node/94/hl-node
objdump -d --start-address=0x4a0e490 --stop-address=0x4a0ea22 artifacts/node/94/hl-node
```

The ELF is authenticated before output creation. Six generated files are `evidence.json`, `branches.tsv`, `calls.tsv`, `dispatch.tsv`, `fields.tsv` and `spans.tsv`. The script parses `.eh_frame`, the ELF section table and `R_X86_64_RELATIVE` records through the shared parsers and standard-library `struct`; only file-backed sections are mapped. The digest, explicit body hashes, instruction forms, table hashes, table bounds and mapped targets must all agree. The README and manifest are authored separately.

## Evidence

All addresses are linked ELF virtual addresses, before load bias. For the selected code, file offset is VA minus `0x1000`, checked from the actual section headers. These are decoded FDE ranges, not proof of original source-function boundaries:

| Descriptive role | FDE half-open interval | Size | FDE record VA |
| --- | --- | ---: | --- |
| Matching-leg builder | `0x49e4210..0x49e4449` | 569 bytes | `0xf23328` |
| Error cleanup dispatcher | `0x4a0e490..0x4a0ea22` | 1,426 bytes | `0x12b75a8` |

The complete bytes and hashes of those ranges are in `evidence.json`; `spans.tsv` selects 21 contiguous instruction ranges and records their exact file offsets and bytes. Eighteen chosen branches, seven call/relocation edges and twelve result-store operands are independently decoded in the corresponding TSV files. The two selected call sites at `0x430ed8d` and `0x430eda7` pass selector 0 and 1 respectively, with output buffers separated by `0xf8` bytes; the preceding instruction bytes are retained in `spans.tsv`. This connects the builder to an already studied matching body without claiming to remap that body.

The additional caller windows are context for the new builder, not a second mapped function. At `0x430e337..0x430e360` the caller requires a key below the available entry count, multiplies the key by `0xf8`, and rejects the 32-bit slot discriminant 2; both failed checks branch to `0x4310e6e`. The resulting slot pointer is saved at `0x430e47c`, restored on the two shown paths at `0x430eb81` and `0x430ebb3`, then placed in the builder context at `0x430ecf6`. This supplies the slot provenance for the record below. The preexisting price-level lifecycle packet establishes this slot family; the present packet does not claim its caller or state mutation as new work.

### Input selection and result fields

In the observed calling convention, `rdi` is the result pointer, `rsi` is a context pointer and `edx` is the selector. For these two call sites, the selector is 0 or 1. The builder loads a pointer at context `+0x00`, chooses the first or second 20-byte field at offsets `0` or `0x14`, and writes that field to result `+0xd0..+0xe3`. It unconditionally calls through relocation slot `0x5773d68`, whose type-8 RELA addend is `0x372f930`; the first 16 bytes returned to its stack result are copied to result `+0x08`.

The builder compares the low selector byte to byte `+0xc2` of the slot addressed by context `+0x18`. Other result fields come from the following sources; a star means dereference the pointer stored at the stated context offset.

| Result offset / width | Equal selector and slot byte | Different selector and slot byte |
| --- | --- | --- |
| `+0x18`, 16 bytes | zero | `*(context + 0x48)` |
| `+0x28`, 40 bytes | slot `+0x68` | `*(context + 0x58)` |
| `+0xc8`, 8 bytes | slot `+0xd8` | `*(context + 0x40)` |
| `+0xe4`, 17 bytes | slot `+0xb1` | `*(context + 0x50)` |

The result's qword at `+0x00` is set to 1 and its qword at `+0x60` to 2. The builder also writes an option-shaped pair at `+0x50` and `+0x58`. The `fields.tsv` stores specify widths and encoded displacements; the source loads, register flow and constant writes are in `spans.tsv`. Gaps in the output are not initialized by every path and must not be inferred to be zero.

### Auxiliary decision and failure

The following is a reconstruction of the selected branches, not a target-execution test. The code writes a pointer to `+0x58` on each zero-tag path. Whether consumers ignore that word is unresolved; it is not observed to be a zero-filled payload.

| Condition | `+0x50` | Observed `+0x58` write | Auxiliary / cleanup |
| --- | ---: | --- | --- |
| selector equals slot byte | 0 | slot pointer | neither |
| selector differs, byte at `*(context + 0x20)` is zero | 0 | pointer stored at context `+0x20` | neither |
| selector differs, byte is nonzero, auxiliary result tag is `0x186` | 1 | auxiliary result qword `+0x08` | auxiliary only |
| selector differs, byte is nonzero, auxiliary result tag differs from `0x186` | 1 | 0 | auxiliary, then cleanup |

The direct call at `0x49e42f6` enters the auxiliary boundary. On error, the builder copies its 96-byte result to a local temporary, calls cleanup at `0x49e437d`, sets the value register to zero, and reaches the shared tag-1 store. No claim is made about what the auxiliary computes or whether its error can unwind during cleanup. An exception would prevent the normal result stores from completing.

### Error cleanup dispatch

Cleanup starts with a 16-bit tag. The first table is selected by tags `0x3a..0xfa` and has 193 relative 32-bit entries. Tags outside that range are checked against `0x14b..0x172`, which selects a second table of 40 entries; tags outside both intervals return directly. The first table has 172 entries to the direct return block and the second has 36. These are table entries, not a count of runtime errors or reachable variants.

For example, tags `0x3b`, `0x4f`, `0x64`, `0x82`, `0x83`, `0xb8`, `0xc2`, `0xc6`, `0xe0`, `0xf8`, `0xfa`, `0x159` and `0x168` select the block that checks the qword at error `+0x08` and, if nonzero, passes the pointer at `+0x10` and that qword through slot `0x576e010`. Its type-8 relocation addend is `0x54c8cb0`; its use as deallocation is an inference from the argument and cleanup context. Tags `0x3a`, `0xc4`, and `0x172` first require a positive signed value at `+0x08`. Further root cases include:

| Tags | Observed selected cleanup arm |
| --- | --- |
| `0x7a`, `0x85` | Load error `+0x08`, load the first qword at that pointer, and tail-jump through the qword it points to. The target and side effects are unresolved. |
| `0xbd` | Load error `+0x08` and tail-jump to `0x4a0ea50`; its body is outside this packet. |
| `0xd1`, `0xd2` | If error `+0x10` is nonzero, pass it and pointer `+0x18` through the same cleanup slot; otherwise return. |
| `0xf6` | Independently gate the `+0x08/+0x10` pair and then the `+0x20/+0x28` pair; the second length is shifted left by four before the shared cleanup tail, with no separate overflow check in the shown arm. A zero first length does not skip the second check. |
| `0xbb`, `0x14b` | Enter bounded nested dispatch on byte `+0x08`; tag `0x14b` has further nested cases. |

The shared slot is consistent with deallocation but its body is not analyzed here. Other targets include indirect destructors and additional tagged cases; their complete behavior is unresolved.

`dispatch.tsv` contains all 296 entries of seven individually bounded tables (the two top-level tables plus five nested tables). Each base and bound is decoded from its RIP-relative LEA and compare, each signed displacement is read directly from ELF bytes, and every destination must lie inside the cleanup FDE. The file is a complete enumeration of these table entries, not proof that each case is reachable from this call path. An out-of-range nested value may have its own code path; it is not represented as a table row. The target status `0x186` bypasses cleanup in the builder.

### Inferences and limits of names

The prior matching packet describes two fill legs, and these two call sites choose opposite 20-byte fields and construct adjacent `0xf8`-spaced results. This supports calling the selected function a matching-leg builder and the 20-byte fields users; those names are not recovered symbols. A 0/1 tag and payload pair is option-shaped, but exact Rust types and ownership are not established. The `decision` helper in the collector expresses the four branch outcomes for the two selectors and represents zero-tag pointer payloads as `None`; it is a reading aid and does not emulate or independently test the target.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No target code was executed, no compiled Rust was compared, and no masking, raw/normalized byte equivalence, helper closure, vtable/data closure, relocation closure beyond the two recorded relocations, or whole-ELF claim is made. The tests use the authenticated target bytes and fixed opcode/target controls; the truth table tests check the stated static interpretation rather than behavior of the captured binary. The exact error types, all cleanup side effects and behavior after a cleanup unwind remain open.

## Results and limitations

The local test module has 14 passing tests, zero skips. It checks identity and mutations to the artifact, an FDE extent, a function byte, a caller slot discriminator, a cleanup size shift, a branch opcode and displacement, a direct call, a relocation addend, dispatch bytes and an out-of-range dispatch target. It also rejects NOBITS and unmapped address ranges and checks equal-side, missing, success and adjacent-to-success error cases in the static decision model. `evidence.json` records the exact selected input hash; `MANIFEST.sha256` records the reusable packet files.

No RE-006 completion gate is requested. The target does not supply a complete source-level type, the external helper bodies and their side effects are not closed, and this bounded record-construction path does not recover the full insert, settlement, or match loop. Next question: recover the auxiliary helper's actual result construction and establish which error tags are reachable here, then compare the resulting leg records and ownership behavior in an authorized offline differential harness.
