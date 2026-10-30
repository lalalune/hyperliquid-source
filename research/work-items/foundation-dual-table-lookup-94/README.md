# foundation-dual-table-lookup-94: what does the byte-indexed dual-table lookup window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window with two padding bytes, the byte-indexed dual-table lookup rule it implements, the exact incoming-call scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of either table entry, the identity or purpose of any caller, and any wider lookup family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a byte index, zero-extended, used to load one 8-byte entry from one table and one signed 4-byte offset from a second table, with the second table's base added back to the offset. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x299e280`, no open pull request title mentions it or dual-table lookup, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, or checked-subtract packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_dual_table_lookup.py --check research/work-items/foundation-dual-table-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_dual_table_lookup -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x299e280 --stop-address=0x299e2a0 artifacts/node/94/hl-node
objdump -d --start-address=0x16505b0 --stop-address=0x1652428 artifacts/node/94/hl-node
objdump -d --start-address=0x1679980 --stop-address=0x167ac43 artifacts/node/94/hl-node
objdump -d --start-address=0x1682090 --stop-address=0x1682217 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its two padding bytes. The `caller.objdump.txt` file retains complete disassembly of the three caller FDEs at `0x16505b0`, `0x1679980`, and `0x1682090`, from which the six call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0xc2280` (this window) and `0xc2294` (the next window), plus the frame records of the three caller FDEs. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0xc2280` describes `[0x299e280, 0x299e29e)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x299e29d` is inside the FDE).
- Two `int3` bytes (`0xcc`) follow at `0x299e29e`–`0x299e29f`, and the next FDE starts exactly at `0x299e2a0` (record at `.eh_frame+0xc2294`, range 467 bytes to `0x299e473`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: byte-indexed dual-table lookup, no calls, no branches

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x299e280` | `lea -0x25a696f(%rip),%rax` | u64-table base `0x3f7918` (RIP-relative: `0x299e287 - 0x25a696f`) |
| `0x299e287` | `movzbl %dil,%ecx` | Byte index, zero-extended |
| `0x299e28b` | `mov (%rax,%rcx,8),%rdx` | u64 entry at index (8-byte entries) |
| `0x299e28f` | `lea -0x25a66f6(%rip),%rsi` | i32-table base `0x3f7ba0` (RIP-relative: `0x299e296 - 0x25a66f6`) |
| `0x299e296` | `movslq (%rsi,%rcx,4),%rax` | i32 entry at index, sign-extended (4-byte entries) |
| `0x299e29a` | `add %rsi,%rax` | Resolved pointer = i32-table base + signed entry |
| `0x299e29d` | `ret` | Returns `(rax, rdx)` |

The rule is therefore: `idx = zero_extend(byte_arg)`; `rdx = u64_table[idx]`; `rax = 0x3f7ba0 + sign_extend(i32_table[idx])`. Both tables live in `.rodata`. The window contains no call opcode and no branch opcode: it is straight-line to `ret`. The byte argument is the only input register read; `rdi`'s upper bytes are ignored by `movzbl`.

Observed table heads (first four entries each, meaning not claimed): u64 table `6, 14, 15, 15`; i32 table `-1664, -1658, -1644, -1629`. Worked edges: index 0 → `(0x3f7520, 6)`; index 1 → `(0x3f7526, 14)`; index 3 → `(0x3f7543, 15)`. One further observed entry is recorded without interpretation: index 5's i32 entry is `-2014208`, resolving to `0x20bfa0`, far from the neighboring entries' resolved pointers (which cluster near `0x3f75xx`). That anomaly is an observed byte fact, not a claimed semantic distinction; the checker does not lock entries beyond the first four of each table.

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly six direct `e8` call sites: `0x16511cc` and `0x1651487` in caller FDE `0x16505b0..0x1652428`; `0x167a6d5`, `0x167a745`, and `0x167a8f6` in caller FDE `0x1679980..0x167ac43`; `0x168214d` in caller FDE `0x1682090..0x1682217`. Each site was confirmed as an instruction start by linear disassembly from its caller FDE start, and objdump resolves each call target to `0x299e280`. The scan is explicitly not a complete xref census.
- No relocation record of any type in `.rela.dyn` names this window as addend (a full `readelf -r` grep for `0x299e280` also finds zero hits). The window is reached by direct calls, not by a data pointer, as far as the retained evidence shows.

## Inferences

- The window is a lookup helper indexed by one byte, returning a resolved pointer and a 64-bit value side by side. That shape is an inference from the instruction sequence, kept separate from the observed rule above.
- The "dual-table lookup" label is an inference, not a source-level name.

## Unknowns

- What either table entry means, what the resolved pointer points to, and what the u64 value represents: unknown, and not claimed.
- The identity, purpose, and argument values of the six callers: unknown, and not claimed. The caller FDE ranges are retained only to anchor the call sites.
- Why index 5's i32 entry resolves far from its neighbors: unknown, and not claimed.
- Whether any caller reaches this window by an indirect call or a data pointer: unknown; the byte-pattern scan is not a complete xref census.

## Limits

- No stdlib type, source-level function, table meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The checker locks only the first four entries of each table; the rest of both tables is unexamined.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
