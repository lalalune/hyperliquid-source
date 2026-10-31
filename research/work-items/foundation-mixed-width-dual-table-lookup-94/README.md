# foundation-mixed-width-dual-table-lookup-94: what does the byte-indexed mixed-width dual-table lookup window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window with two padding bytes, the byte-indexed mixed-width dual-table lookup rule it implements, the exact incoming-call scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of either table entry, the identity or purpose of the caller, and any wider lookup family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a byte index, zero-extended, used to load one 8-byte entry from one table and one signed 4-byte offset from a second table, with the second table's base added back to the offset. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This is the third dual-table lookup after packets #24 (`0x299e280`) and #63 (`0x4e48600`), and that fact is stated head-on rather than buried: what justifies this window on its own merits is the mixed-width second table. Packet #24's second table is a plain i32 value table whose entries are read as values, and packet #63's second table is a load-time qword table; here the second table's entries are relative i32 offsets that only become pointers when the table base is added back (the `add %rsi,%rax` after the `movslq`). The three windows are not merged, and no dual-table census is claimed.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x29d7fc0`, no open pull request title mentions it or mixed-width dual-table lookup, and its bytes overlap nothing in packets #1–#73.

## Scout correction

The round-11 scout note listed this window's table bases as `0x41aa0`/`0x42728` with table heads `[8, 2008143, 90776192, 8, 2008143, 90776216, 8, 2008143]` and `[90778944, 8, 2047759, 90778968, 8, 2047759, 90778992, 8]`. Those values are real bytes, but at the wrong addresses: `0x41aa0`/`0x42728` are not the lea targets, and the second list reads the i32 table at an 8-byte stride instead of the 4-byte stride the `movslq (%rsi,%rcx,4)` instruction actually uses. The objdump-annotated lea targets are `0x4024a0`/`0x402728`, and the verified heads below replace the scout's tables everywhere. The scout's rule shape (mixed-width dual-table lookup, one caller) and FDE range verified exactly; only the table bases and heads were wrong.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_mixed_width_dual_table_lookup.py --check research/work-items/foundation-mixed-width-dual-table-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_mixed_width_dual_table_lookup -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x29d7fc0 --stop-address=0x29d7fe0 artifacts/node/94/hl-node
objdump -d --start-address=0x29d7fe0 --stop-address=0x29d8a0e artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its two padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE at `0x29d7fe0`, from which the single call site was confirmed as an instruction start. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0xc52e4` (this window), `0xc52f8` (the next record in `.eh_frame` order), and `0x439154` (the caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` and `.rodata` have equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0xc52e4` describes `[0x29d7fc0, 0x29d7fde)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x29d7fdd` is inside the FDE).
- Two `int3` bytes (`0xcc`) follow at `0x29d7fde`–`0x29d7fdf`, and the address-order next FDE starts exactly at `0x29d7fe0` (the caller FDE, record at `.eh_frame+0x439154`, range to `0x29d8a0e`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately. The next record in `.eh_frame` order (offset `0xc52f8`, PC `0x29d8a10..0x29d8bfd`) is a different function and is locked only as the section-order neighbor, not as the address-order successor.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: byte-indexed mixed-width dual-table lookup, no calls, no branches

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x29d7fc0` | `lea -0x25d5b27(%rip),%rax` | u64-table base `0x4024a0` (RIP-relative: `0x29d7fc7 - 0x25d5b27`) |
| `0x29d7fc7` | `movzbl %dil,%ecx` | Byte index, zero-extended |
| `0x29d7fcb` | `mov (%rax,%rcx,8),%rdx` | u64 entry at index (8-byte entries) |
| `0x29d7fcf` | `lea -0x25d58ae(%rip),%rsi` | i32-table base `0x402728` (RIP-relative: `0x29d7fd6 - 0x25d58ae`) |
| `0x29d7fd6` | `movslq (%rsi,%rcx,4),%rax` | i32 entry at index, sign-extended (4-byte entries) |
| `0x29d7fda` | `add %rsi,%rax` | Resolved pointer = i32-table base + signed entry |
| `0x29d7fdd` | `ret` | Returns `(rax, rdx)` |

The rule is therefore: `idx = zero_extend(byte_arg)`; `rdx = u64_table[idx]`; `rax = 0x402728 + sign_extend(i32_table[idx])`. Both tables live in `.rodata`. The window contains no call opcode and no branch opcode: it is straight-line to `ret`. The byte argument is the only input register read; `rdi`'s upper bytes are ignored by `movzbl`.

Observed table heads (first eight entries each, meaning not claimed): u64 table `6, 14, 15, 15, 13, 32, 28, 28`; i32 table `-3447, -3441, -3427, -3412, -3397, -2058120, -3384, -3356`. Worked edges: index 0 → `(0x4019b1, 6)`; index 1 → `(0x4019b7, 14)`; index 3 → `(0x4019d4, 15)`. One further observed entry is recorded without interpretation: index 5's i32 entry is `-2058120`, resolving to `0x20bfa0`, far from the neighboring entries' resolved pointers (which cluster near `0x4019xx`). That anomaly is an observed byte fact, not a claimed semantic distinction; the checker locks the first eight entries of each table, and the rest of both tables is unexamined.

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` call site: `0x29d81b4` (bytes `e8 07 fe ff ff`), in caller FDE `0x29d7fe0..0x29d8a0e`. The site was confirmed as an instruction start by linear disassembly from its caller FDE start, and objdump resolves the call target to `0x29d7fc0`. The scan is explicitly not a complete xref census.
- On the call path, the caller loads the argument with `mov 0x108(%rsp,%rbx,1),%edi` at `0x29d81ad`, immediately before the call; the window reads only `dil`. The call is reached from the `je` at `0x29d8199` when the compared qword at `0x100(%rsp,%rbx,1)` is zero; the fall-through path loads other registers and jumps past the call. Caller purpose is not claimed.
- No relocation record of any type in any `.rela.*` section names this window as addend (a full `readelf -r` scan of 80,300 entries finds zero hits). The window is reached by a direct call, not by a data pointer, as far as the retained evidence shows.
- Nearest claimed window: byte-indexed dual-table lookup `0x299e280` (packet #24), `0x39d40` away.

## Inferences

- The window is a lookup helper indexed by one byte, returning a resolved pointer and a 64-bit value side by side. That shape is an inference from the instruction sequence, kept separate from the observed rule above.
- The "mixed-width dual-table lookup" label is an inference, not a source-level name.

## Unknowns

- What either table entry means, what the resolved pointer points to, and what the u64 value represents: unknown, and not claimed.
- The identity, purpose, and argument values of the caller: unknown, and not claimed. The caller FDE range is retained only to anchor the call site.
- Why index 5's i32 entry resolves far from its neighbors: unknown, and not claimed.
- Whether any caller reaches this window by an indirect call or a data pointer: unknown; the byte-pattern scan is not a complete xref census.

## Limits

- No stdlib type, source-level function, table meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The checker locks only the first eight entries of each table; the rest of both tables is unexamined.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
