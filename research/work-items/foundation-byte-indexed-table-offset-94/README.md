# foundation-byte-indexed-table-offset-94: what does the byte-indexed table offset window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 89-byte FDE window with 7 padding bytes, the byte-indexed table offset rule with its exact constants and field offsets, the exact incoming-call scan result (three direct sites in three caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the node fields mean, what the table entries and the selector byte represent, any wider table-offset family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a computed pointer = base + table[edx] + 224 * selector-byte, with the selector byte optionally reported through an out-param. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x54ccfb0`, no open pull request title mentions it or byte-indexed-table-offset, and its bytes overlap nothing in packets #1–#105.

## Scout note

The round-16 scout note listed this window (ranked #4, the last ranked item) with FDE `[0x54ccfb0, 0x54cd009)`, 89 bytes, 7 padding bytes, three direct callers (all boundary-confirmed), no naming relocation, and nearest claimed window bit-writer drain `0x5494050` (packet #84) `0x38f60` away. Every element verified exactly; no scout correction was needed.

## Caller caveat

Three direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x55557a3` (FDE `0x5554b50..0x5555bcc`), `0x5556447` (FDE `0x5555bd0..0x555661f`), and `0x555755c` (FDE `0x5557510..0x5557617`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

## Dual-table distinction, stated head-on

Packets #24/#63/#74 load two table entries into registers. This window is different: it adds one table entry to a base pointer plus a scaled selector byte, and stores the selector itself out through an optional out-param. One table entry, one scaled byte, one optional out store — not a dual load. No shared primitive is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_indexed_table_offset.py --check research/work-items/foundation-byte-indexed-table-offset-94/evidence.json
python3 -m unittest tests.test_foundation_byte_indexed_table_offset -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54ccfb0 --stop-address=0x54cd010 artifacts/node/94/hl-node
objdump -d --start-address=0x5554b50 --stop-address=0x5555bcc artifacts/node/94/hl-node
objdump -d --start-address=0x5555bd0 --stop-address=0x555661f artifacts/node/94/hl-node
objdump -d --start-address=0x5557510 --stop-address=0x5557617 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 7 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the three caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2c0624` (this window), `0x2c0638` (the next FDE), `0x2cf138`, `0x2cf164`, and `0x2cf364` (the three caller FDEs), plus the CIE at offset `0` (this window, the next FDE, and all three caller FDEs — all four records name CIE 0). The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c0624` describes `[0x54ccfb0, 0x54cd009)`, 89 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Seven int3 padding bytes follow (`cc` x 7 at `0x54cd009..0x54cd010`): the next FDE starts exactly at `0x54cd010` (record at `.eh_frame+0x2c0638`, range to `0x54cd781`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the standard indirect-branch landing pad; that is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x54ccfb0`. The index is zero-extended to 64 bits (both `mov %edx,%edx` sites); the table entry is zero-extended by the `mov`-into-`r9d` load (not `movslq`).

- Offset `0x00`: `endbr64` — indirect-branch landing pad.
- Offset `0x04`: `mov %rsi,%rax` — input base preserved as the return accumulator.
- Offset `0x07`: `test %rdi,%rdi` — null struct test.
- Offset `0x0a`: `je 0x54ccfe8` — null struct takes the zero path.
- Offset `0x0c`: `cmpq $0x0,0x90(%rdi)` — presence field compare.
- Offset `0x14`: `je 0x54ccfe8` — zero presence field takes the same zero path.
- Offset `0x16`: `mov %edx,%edx` — index zero-extended.
- Offset `0x18`: `movzbl 0xa1(%rdi,%rdx,1),%r8d` — selector byte load.
- Offset `0x21`: `lea 0x0(,%r8,8),%rsi` — selector times eight.
- Offset `0x29`: `sub %r8,%rsi` — selector times seven.
- Offset `0x2c`: `shl $0x5,%rsi` — selector times 224.
- Offset `0x30`: `jmp 0x54ccfef` — join to the shared tail.
- Offset `0x32`: `nopw 0x0(%rax,%rax,1)` — 6-byte intra-body alignment padding between the jmp and the zero path; it is never executed on any path.
- Offset `0x38`: `xor %esi,%esi` — zero path: index term zeroed.
- Offset `0x3a`: `xor %r8d,%r8d` — zero path: selector zeroed.
- Offset `0x3d`: `mov %edx,%edx` — join path: index zero-extended again.
- Offset `0x3f`: `test %rcx,%rcx` — out-param null test.
- Offset `0x42`: `je 0x54ccff7` — null out-param skips the store.
- Offset `0x44`: `mov %r8d,(%rcx)` — selector stored out (32-bit).
- Offset `0x47`: `lea 0x2cccc2(%rip),%rcx` — rip-relative table base `0x5799cc0`.
- Offset `0x4e`: `mov (%rcx,%rdx,4),%r9d` — 32-bit table entry load, zero-extended.
- Offset `0x52`: `add %r9,%rax` — table entry added to the base.
- Offset `0x55`: `add %rsi,%rax` — scaled selector added.
- Offset `0x58`: `ret` — single return.

All four branches are forward and land inside the window; no branch leaves the window, and no call sits inside it.

### Decoded rule

Let `base = rsi` (input base), `present = [rdi+0x90]` (64-bit), `index = edx` (zero-extended 32-bit), `selector = byte [rdi + index + 0xa1]`, `table = [0x5799cc0 + index*4]` (32-bit, zero-extended), and `out = rcx`. The window returns in `rax`:

- If `rdi == 0` or `present == 0`: `selector = 0`, `term = 0`.
- Otherwise: `term = selector * 224`.
- If `out != 0`: `[out] = selector` (32-bit store).
- `rax = base + table + term` (64-bit wrapping).

No field besides the optional out-param is written anywhere. Note the asymmetry the bytes force: the table entry is zero-extended (`mov` into `r9d`), not sign-extended — a `0x80000000` entry adds `0x80000000` rather than subtracting. The checker locks this with a dedicated edge case and claims no meaning for the table values.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` sites whose rel32 lands on the window start: `0x55557a3`, `0x5556447`, and `0x555755c`. Each was confirmed as an instruction start by linear disassembly from its caller FDE start, and all three caller FDEs are retained in `caller.objdump.txt` with their frame records in `frames.txt`. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation is reported as a scan result only; it does not identify the window's provenance.

### Nearest claimed window

Bit-writer drain `0x5494050` (packet #84) sits `0x38f60` below this window. The two windows share no field offset, constant, or rule shape: #84 drains a bit-writer counter with byte-pair emission, while this window adds a table entry to a base plus a scaled selector byte and stores the selector out. No shared primitive is claimed.

## Inferences

- The "byte-indexed table offset" label is an inference from the base + table[index] + 224 * selector shape; the window itself names nothing.
- The `+0x90` field looks like a presence/validity flag gating the selector load, and the `+0xa1` byte looks like a per-index selector, but what the struct and the table contain is not claimed.
- The 224 multiplier (224 = 7 * 32) suggests a fixed-size entry stride, but the entry size and layout are not claimed.

## Unknowns

- What the struct fields, the table entries, and the selector byte represent, and what the returned pointer points to.
- Whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- What the three callers do with the returned pointer and the stored selector after the window returns.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
