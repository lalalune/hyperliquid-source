# foundation-flag-set-conditional-clear-94: what does the flag-set plus conditional clear window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window with two padding bytes, the flag-set plus conditional clear rule with its exact field offsets and branch target, the exact incoming-call scan result (seven direct sites, each boundary-confirmed), and the zero-relocation data edge.
- Excluded: what the flag field and the pointer field mean, what reads the flag or the cleared byte, any wider flag-setter family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a flag-set plus conditional clear that stores 1 into a dword field and, when its loaded pointer is non-null, clears the byte that pointer points at. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x53cf560`, no open pull request title mentions it or flag-set-conditional-clear, and its bytes overlap nothing in packets #1–#97.

## Scout note

The round-15 scout note listed this window (ranked #2) with FDE `[0x53cf560, 0x53cf57e)`, 30 bytes, 2 padding bytes, seven direct callers all boundary-confirmed, no naming relocation, and nearest claimed window gated two-field copy `0x53b1120` (packet #93) `0x1e440` away. Every scouted element verified exactly, including the full body, the branch target, all seven caller sites and their FDE ranges, and the zero-relocation scan.

One scout-order correction, stated head-on: the scout note described the rule as "store 1, then load the pointer and clear". The bytes show the opposite order: the pointer load sits at offset `0x04` and the flag store at offset `0x0b` — the load happens first. The observable behavior is unchanged (the two fields are distinct, so the store cannot affect the loaded value), and the corrected order is what the checker locks and what the rule below states.

## Field-offset caveat

Packet #17's flag-OR window also touches field `+0x1a0`, but with a different rule: it ORs a table entry indexed by a byte into field `+0x1a0`. This window loads the pointer field `[rdi+0x1a0]` and clears the byte that pointer points at, while storing 1 into a different field `[rdi+0x108]`. Same field offset, different rule and different struct role — no shared primitive is claimed.

## Caller caveat

Seven direct `e8` call sites target this window, and each was confirmed as an instruction start by linear disassembly from its caller FDE start (not just by the byte-pattern scan). The seven caller FDEs are retained in full in `caller.objdump.txt`; caller purposes are not claimed, and no caller census is built. The seven caller FDEs share one CIE at `.eh_frame+0x6205d0`, distinct from this window's CIE at offset 0; the checker locks both CIEs and all nine FDE records.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_flag_set_conditional_clear.py --check research/work-items/foundation-flag-set-conditional-clear-94/evidence.json
python3 -m unittest tests.test_foundation_flag_set_conditional_clear -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53cf560 --stop-address=0x53cf580 artifacts/node/94/hl-node
objdump -d --start-address=<caller FDE start> --stop-address=<caller FDE end> artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its two padding bytes. The `caller.objdump.txt` file retains complete disassembly of all seven caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b6740` (this window), `0x2b6754` (the next FDE), and the seven caller FDE offsets, plus the shared CIE at offset 0 and the caller CIE at offset `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b6740` describes `[0x53cf560, 0x53cf57e)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Two `int3` bytes follow: the next FDE starts exactly at `0x53cf580` (record at `.eh_frame+0x2b6754`, range to `0x53cf5ee`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x427760`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: flag-set plus conditional clear, one branch, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8b 87 a0 01 00 00 | mov 0x1a0(%rdi),%rax |
| 0x0b | c7 87 08 01 00 00 01 00 00 00 | movl $0x1,0x108(%rdi) |
| 0x15 | 48 85 c0 | test %rax,%rax |
| 0x18 | 74 03 | je 0x53cf57d |
| 0x1a | c6 00 00 | movb $0x0,(%rax) |
| 0x1d | c3 | ret |

Rule, derived step by step: the pointer field `[rdi+0x1a0]` is loaded into rax first; then 1 is stored into the dword field `[rdi+0x108]`; then rax is tested against zero, and the branch jumps to `ret` when it is zero, so the null path skips the clear but still performs the flag store. Otherwise the byte at `[rax]` is written to 0 and control falls through to `ret`. No return value is claimed: on the null path rax is 0, on the clear path rax still holds the pointer. The branch target is exact: the `je` at offset `0x18` is 2 bytes with displacement `0x03`, landing on the `ret` at offset `0x1d` (`0x53cf57d`). No call opcode appears inside the window.

### Incoming calls: seven direct sites, each boundary-confirmed

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly seven direct `e8` sites whose rel32 lands on the window start — explicitly not a complete xref census. Each site was confirmed as an instruction start by linear disassembly from its caller FDE start, and objdump resolves each call target to `0x53cf560`:

| Call site | Call bytes | Caller FDE |
| --- | --- | --- |
| 0x51a018c | e8 cf f3 22 00 | 0x519fa40..0x51a045d |
| 0x51a3bd0 | e8 8b b9 22 00 | 0x51a2950..0x51a3cd9 |
| 0x51d3c4e | e8 0d b9 1f 00 | 0x51d2d90..0x51d3da9 |
| 0x51df28d | e8 ce 02 1f 00 | 0x51ded50..0x51dfbb9 |
| 0x536b50c | e8 4f 40 06 00 | 0x5369ad0..0x536baa8 |
| 0x537d1a0 | e8 bb 23 05 00 | 0x5379eb0..0x537dd61 |
| 0x53d0433 | e8 28 f1 ff ff | 0x53d0390..0x53d044d |

Caller purposes are not claimed, and no caller setup pattern is asserted: the callers are reported as a site list with their FDE ranges only.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere. The "flag-set plus conditional clear" label is an inference, kept separate from the observed rule.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).

## Unknowns

- What the flag field `[rdi+0x108]` and the pointer field `[rdi+0x1a0]` mean, and what reads the flag or the cleared byte.
- Whether any caller depends on the flag store, the byte clear, or both.
- Which source-level function, if any, this window corresponds to.
