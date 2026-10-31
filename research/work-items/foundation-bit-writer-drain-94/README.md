# foundation-bit-writer-drain-94: what does the bit-writer drain window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 136-byte FDE window with eight padding bytes, the bit-writer drain rule with its exact ==16 flush case, the exact incoming-call scan result (26 direct sites in exactly 4 caller FDEs, each boundary-confirmed), and the no-naming-relocation scan result.
- Excluded: what the buffered bits mean, the identity or purpose of any caller, any wider bit-writer family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a bit-writer drain that flushes a buffered accumulator to an output buffer. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5494050`, no open pull request title mentions it or bit-writer-drain, and its bytes overlap nothing in packets #1–#83.

## Scout note

The round-13 scout note listed this window (ranked #2) with FDE `[0x5494050, 0x54940d8)`, 136 bytes, 8 padding bytes, twenty-six direct callers from at least four caller FDEs, no naming relocation, and nearest claimed window byte-class test `0x5430860` (packet #64) `0x637f0` away. Every element verified exactly, including the full body, both branch targets, all 26 caller sites and their call bytes, and the zero naming relocations. One refinement, not a scout correction: the scout's "at least four caller FDEs, plus 14 more unchecked" resolves to exactly four caller FDEs holding all 26 sites (3 + 3 + 4 + 16), each site boundary-confirmed. No numeric correction to the scout's numbers was needed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bit_writer_drain.py --check research/work-items/foundation-bit-writer-drain-94/evidence.json
python3 -m unittest tests.test_foundation_bit_writer_drain -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5494050 --stop-address=0x54940e0 artifacts/node/94/hl-node
objdump -d --start-address=0x5489a10 --stop-address=0x548a2ef artifacts/node/94/hl-node
objdump -d --start-address=0x548a2f0 --stop-address=0x548a894 artifacts/node/94/hl-node
objdump -d --start-address=0x548a8a0 --stop-address=0x548b03b artifacts/node/94/hl-node
objdump -d --start-address=0x548b640 --stop-address=0x548cebc artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its eight padding bytes. The `caller.objdump.txt` file retains complete disassembly of all four caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2bf2a8` (this window), `0x2bf2bc` (the next FDE), and `0x2beb2c`, `0x2beb78`, `0x2bebf8`, `0x2bed68` (the four caller FDEs), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2bf2a8` describes `[0x5494050, 0x54940d8)`, 136 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Eight `int3` bytes follow: the next FDE starts exactly at `0x54940e0` (record at `.eh_frame+0x2bf2bc`, range to `0x5494222`). The unwind-index stride is therefore 144 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: bit-writer drain, no calls, two branches

The window reads a counter dword at `[rdi+0x1734]`, an accumulator word at `[rdi+0x1730]`, an output buffer pointer at `[rdi+0x10]`, and a write position qword at `[rdi+0x28]`. It writes only through the buffer pointer and those three fields, and returns nothing.

- Counter == 16 (the `cmp $0x10,%eax; je 0x5494090` path): emit the low byte of the accumulator word at buffer + position, position += 1; reload the position and emit the high byte (the byte at `[rdi+0x1731]`) at buffer + position, position += 1; accumulator word = 0; counter = 0; ret. Total: two bytes emitted, position += 2, state reset.
- Counter <= 7, signed (the `cmp $0x7,%eax; jle 0x549408d` path): ret with no emit and no state change.
- Every other counter value (the fall-through path): emit the low byte of the accumulator word at buffer + position, position += 1; counter -= 8; accumulator word >>= 8 (logical word shift); ret.

In the valid counter range 0..16, the fall-through path covers exactly 8..15. The branch structure itself does not separately gate values above 16: such a value would take the same one-byte path, and the checker's rule model restates the branches exactly rather than assuming the range. The two emit paths must not be merged: the flush path clears the accumulator and counter, while the one-byte path shifts the accumulator and subtracts 8 from the counter, leaving different state for the next drain.

A 2-byte `xchg %ax,%ax` alignment nop at `0x549408e` sits inside the FDE between the one-byte path's `ret` and the flush path's entry; it is targeted by no branch and is locked as bytes, not behavior.

### Incoming calls: a shared helper, stated head-on

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly 26 direct `e8` sites landing on this window — explicitly not a complete xref census. All 26 were confirmed as instruction starts by linear disassembly from their caller FDE starts, and all 26 call-byte sequences are locked by the checker. The sites fall in exactly four caller FDEs: `0x5489a10..0x548a2ef` (3 sites), `0x548a2f0..0x548a894` (3 sites), `0x548a8a0..0x548b03b` (4 sites), and `0x548b640..0x548cebc` (16 sites). This is therefore a shared bit-writer method, not a one-off helper: the packet binds the drain rule exactly and claims no single-caller provenance and no caller purpose.

### Data edges

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The "bit-writer drain" label is an inference from the observed rule (a buffered accumulator flushed byte by byte to an output buffer). The rule itself — counter, accumulator, buffer, position, and the exact ==16 flush case — is observed, not inferred.
- The counter is read as a bit count (0..16 in normal use) and the accumulator as a 16-bit buffer; both readings are consistent with the branch thresholds and the word-width operations, but the bytes alone do not prove what fills them.

## Unknowns

- What the buffered bits encode, what fills the accumulator, and what consumes the output buffer.
- The identity, purpose, and argument setup of any of the 26 callers beyond their call bytes and FDE ranges.
- Whether counters above 16 ever occur in practice; the bytes route them to the one-byte path, but no reachable-state claim is made.
- The source-level function, type, or library provenance of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
