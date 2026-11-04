# RE-002: node #115 ELF program-header table and static TLS layout

- Component ID: RE-002 (build provenance / binary closure, load-segment and TLS layout leaf).
- Target release and full SHA-256: Linux x86-64 hl-node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no reference source is used.
- Claim status: observation (every value below is read from the pinned bytes).
- Scope included and excluded: included is the static ELF64 program-header table, the segment map it defines, and the static TLS initialization image (`.tdata`/`.tbss`). Excluded is execution of the target, dynamic relocation processing, lazy binding, runtime thread-local storage initialization by the loader, and any behaviour claim.

## Bounded question

Which exact program headers does node #115 carry, and what file-offset-to-virtual-address mapping plus static TLS block does that table define? The answer fixes the address coordinate system used by every other #115 record and describes the one PT_TLS segment without executing the image.

## Reproduce

No target execution and no copy of the target is made. The verifier reads `artifacts/node/115/hl-node` in place, authenticates its SHA-256, then parses the ELF header, the program-header table and the section header string table in pure Python and prints the derived record before its assertions.

```sh
python3 test-results/slop-workbench/packet-2c6ec29f2b07.py
```

Coordinates are ELF virtual addresses (VA) for `vaddr`/`addr` and raw file offsets for `offset`. The image is a PIE (`e_type` 3) with `e_machine` 62; file offsets and addresses therefore differ for all but the first load segment.

## Evidence

ELF identity: `e_type` 3 (ET_DYN), `e_machine` 62 (EM_X86_64), `e_phnum` 12, program-header table at file offset `0x40` with `e_phentsize` 56, i.e. 672 bytes ending at `0x2e0`.

| # | Type | Flags | Offset | Vaddr | Filesz | Memsz | Align |
| ---: | --- | --- | --- | --- | ---: | ---: | --- |
| 0 | PT_PHDR | 0x4 | 0x40 | 0x40 | 672 | 672 | 0x8 |
| 1 | PT_INTERP | 0x4 | 0x2e0 | 0x2e0 | 28 | 28 | 0x1 |
| 2 | PT_LOAD | 0x4 | 0x0 | 0x0 | 21070420 | 21070420 | 0x1000 |
| 3 | PT_LOAD | 0x5 | 0x1418300 | 0x1419300 | 83724448 | 83724448 | 0x1000 |
| 4 | PT_LOAD | 0x6 | 0x63f0ba0 | 0x63f2ba0 | 1031808 | 1033312 | 0x1000 |
| 5 | PT_LOAD | 0x6 | 0x64eca20 | 0x64efa20 | 66536 | 2330372 | 0x1000 |
| 6 | PT_TLS | 0x4 | 0x63f0ba0 | 0x63f2ba0 | 2848 | 4480 | 0x10 |
| 7 | PT_DYNAMIC | 0x6 | 0x64dd248 | 0x64df248 | 528 | 528 | 0x8 |
| 8 | PT_GNU_RELRO | 0x4 | 0x63f0ba0 | 0x63f2ba0 | 1031808 | 1033312 | 0x1 |
| 9 | PT_GNU_EH_FRAME | 0x4 | 0xb9ea40 | 0xb9ea40 | 1082516 | 1082516 | 0x4 |
| 10 | PT_GNU_STACK | 0x6 | 0x0 | 0x0 | 0 | 0 | 0x0 |
| 11 | PT_NOTE | 0x4 | 0x2fc | 0x2fc | 68 | 68 | 0x4 |

Segment consequences visible in the table alone:

- The four PT_LOAD segments start at VA `0x0`, `0x1419300`, `0x63f2ba0`, `0x64efa20`; each has `align` 0x1000. Only the first has `offset == vaddr`; from segment 3 on the address is the file offset plus a constant per-segment bias (`0x1000` for segment 3, `0x2000` for segments 4, 6 and 8, `0x3000` for segment 5).
- Segments 4 and 5 carry `memsz > filesz` (1,504 and 2,263,836 bytes of zero fill respectively), and segment 5 is the writable data/BSS tail (`memsz` 2,330,372 against `filesz` 66,536).
- PT_GNU_RELRO covers exactly the filesz extent of segment 4 (`0x63f2ba0` + 1,031,808), so the read-only data beyond that point is the relro-protected region.
- PT_TLS block: exactly one segment, `filesz` 2,848, `memsz` 4,480, so 1,632 bytes of `.tbss` zero fill. Its `memsz` (4,480) is not a multiple of anything but its `align` 0x10, and the `.tdata`/`.tbss` split below sums to the same 1,632. The 2,848-byte initialization image at file offset `0x63f0ba0` hashes to `3a3c3472fbb12b91dc0f2b0ea7e01917a9d6879f53fe59cbd79c17a5a6cb137c`; its first 64 bytes are `0000000000000000000000000000000008000000000000000000000000000000` followed by 32 zero bytes.
- The four PT_LOAD filesz values sum to 105,893,212, which is 2,820 bytes short of the 105,896,032-byte file: segment 0 ends at file offset 21,070,420 while segment 3 begins at 21,070,592, a 172-byte gap, and the load extents end at file offset 105,893,384, leaving 2,648 bytes at the tail outside every PT_LOAD segment. That tail content is not analysed in this packet.
- PT_GNU_STACK carries flags 0x6 (read+writable, not executable) with filesz/memsz 0, so the executable stack is not requested; this is a static header observation only, not a runtime kernel check.

TLS sections (SHF_TLS = 0x400):

| Section | Flags | Addr | Offset | Size | Addralign |
| --- | --- | --- | --- | ---: | ---: |
| .tdata | 0x403 | 0x63f2ba0 | 0x63f0ba0 | 2848 | 8 |
| .tbss | 0x403 | 0x63f36c0 | 0x63f16c0 | 1632 | 16 |

`.tdata` filesz matches the PT_TLS `filesz` (2848) and starts at the same vaddr; `.tbss` contributes the remaining 1,632 bytes to `memsz` 4,480. The `.tbss` offset is a placeholder inside the segment's file extent and is not read as data.

## Implementation and comparison

Not applicable: this packet records ELF layout, not recovered Rust semantics. No Rust path, Cargo.lock or byte comparison is claimed, and no normalization mask exists because no comparison is made. The machine-readable form of every value above is `evidence.json`; a corruption control lives in the committed checker (`tools/foundation_program_headers.py`) and its test (`tests/test_foundation_program_headers.py`), which re-derives the same fields and rejects an altered table, a wrong PT_TLS hash and a malformed manifest.

## Results and limitations

Observed and recorded: 12 program headers, 1 PT_TLS segment, 2 TLS sections, the per-segment offset/vaddr bias, the zero-fill extents and the TLS image digest. Recorded denominator: 12 of 12 program headers, 2 of 2 TLS sections, 1 of 1 TLS segment.

Limits:

- Static bytes only. The captured node was not executed, executed, emulated or copied; nothing here is a runtime observation.
- No dynamic-linking, relocation, symbol-version or lazy-binding claim. PT_DYNAMIC is present but its entries are not interpreted here.
- No claim about how the loader initialises thread-local storage at runtime, only the static image and its sizes.
- No function boundary, component, gate or progress claim. No reconstruction completion is implied.
- Not verified: whether the two writable PT_LOAD segments' zero fill is fully addressed at runtime, the meaning of the `.tbss` file offset, and any behaviour of the code that reads TLS variables.

Next question: bind the PT_DYNAMIC entries (DT_NEEDED, DT_FLAGS, DT_RELR presence) to the shared-library identity of this same target, using the recorded program headers as the coordinate base.
