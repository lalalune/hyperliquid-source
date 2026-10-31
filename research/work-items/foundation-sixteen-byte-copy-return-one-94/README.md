# foundation-sixteen-byte-copy-return-one-94: what does the sixteen-byte copy window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window with two padding bytes, the sixteen-byte copy rule with its exact operand offsets, the exact incoming-call scan result (zero direct sites), and the single relocation slot.
- Excluded: what the copied bytes mean, what reads them, any wider copy family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a sixteen-byte copy that moves one unaligned vector from a computed source to a computed destination and returns the constant 1. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5454710`, no open pull request title mentions it or sixteen-byte-copy-return-one, and its bytes overlap nothing in packets #1–#95.

## Scout note

The round-14 scout note listed this window (backup B4) with FDE `[0x5454710, 0x545472e)`, 30 bytes, 2 padding bytes, zero direct callers, one R_X86_64_RELATIVE slot (`0x57675a0`), and nearest claimed window byte-class test `0x5430860` (packet #64) `0x23eb0` away. Every element verified exactly, including the full body, the zero incoming sites, and the single slot address. No numeric correction to the scout's numbers was needed.

## Thinness, stated head-on

This window is thin, and that is all that is claimed for it: it is a straight-line copy of exactly 16 bytes plus a constant return, with no gate, no branch, and no call. Its value as a packet is the exact operand lock (destination `[rdx+8]`, source base `[[rsi+0x10]+8]` minus `0x10`, unaligned vector width) and the exact data edges (zero direct callers, one naming slot), not any claim that the copy itself is distinctive. Nothing about the copied payload's meaning is asserted.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_sixteen_byte_copy_return_one.py --check research/work-items/foundation-sixteen-byte-copy-return-one-94/evidence.json
python3 -m unittest tests.test_foundation_sixteen_byte_copy_return_one -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5454710 --stop-address=0x5454730 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its two padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2bc9a4` (this window) and `0x2bc9b8` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2bc9a4` describes `[0x5454710, 0x545472e)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Two `int3` bytes follow: the next FDE starts exactly at `0x5454730` (record at `.eh_frame+0x2bc9b8`, range to `0x545476d`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x4ac910`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: sixteen-byte copy, no branches, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8b 42 08 | mov 0x8(%rdx),%rax |
| 0x08 | 48 8b 56 10 | mov 0x10(%rsi),%rdx |
| 0x0c | 48 8b 52 08 | mov 0x8(%rdx),%rdx |
| 0x10 | f3 0f 6f 42 f0 | movdqu -0x10(%rdx),%xmm0 |
| 0x15 | 0f 11 00 | movups %xmm0,(%rax) |
| 0x18 | b8 01 00 00 00 | mov $0x1,%eax |
| 0x1d | c3 | ret |

Reading it step by step, with the argument registers as they arrive:

1. `dest = [rdx+8]` — the destination pointer is loaded from the first argument's +0x8 field.
2. `mid = [rsi+0x10]` — an intermediate pointer is loaded from the second argument's +0x10 field.
3. `q = [mid+8]` — the source base is loaded from the intermediate pointer's +0x8 field.
4. `xmm0 = [q-0x10]` — 16 bytes are loaded from sixteen bytes *below* the source base. The -0x10 displacement is part of the instruction, not a correction: the source address is q-0x10, and the copy width is exactly the 16 bytes of one xmm register.
5. `[dest] = xmm0` — the 16 bytes are stored at the destination. Both the load (`movdqu`) and the store (`movups`) are unaligned vector operations, so no alignment of either address is required or claimed.
6. `eax = 1; ret` — the return value is the constant 1, set unconditionally. No condition in the window selects any other return value, and no flag or field is tested anywhere in the body.

No field is written except the 16 destination bytes themselves: the three pointer loads only read, and the vector pair is the single store. The window contains no call opcode and no branch opcode at all — it is straight-line from `endbr64` to `ret`.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x57675a0` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). It is reported as a slot list only; no meaning is claimed for the table it belongs to, and the slot does not identify the window's provenance.

## Inferences

- The "sixteen-byte copy with return 1" label is an inference from the observed instruction sequence, kept separate from the rule above. The rule itself (operands, width, constant return) is observed, not inferred.
- The two argument registers are described only as pointer arguments: `rdx` supplies the destination through its +0x8 field, `rsi` supplies the source chain through its +0x10 field. No struct type, field name, or caller purpose is inferred from them.
- The constant return 1 is consistent with a success/presence convention, but no such convention is claimed: the window may return 1 for reasons outside its own bytes, and this packet asserts only that 1 is what it returns.

## Unknowns

- What the 16 copied bytes represent, and what reads them after the copy.
- Whether any caller passes overlapping source and destination regions; the vector move's behavior in that case is not characterized here beyond the instruction semantics.
- Which source-level function, if any, this window belongs to; the nearest-symbol label is disclaimed above.
- Whether indirect callers or tail jumps reach this window; the scan covers direct `e8` sites only.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
