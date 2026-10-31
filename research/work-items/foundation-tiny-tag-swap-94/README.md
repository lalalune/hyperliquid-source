# foundation-tiny-tag-swap-94: what does the tiny tag-swap window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 24-byte FDE window with eight padding bytes, the tiny tag-swap rule with its exact exchange semantics, the exact incoming-call scan result (zero direct sites), and the 36-slot relocation list.
- Excluded: what the tag means, who reads the stored byte, any wider tag family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a tiny tag-swap that stores 0, 2, or 1 by input byte and returns the previous stored byte. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4f7fb20`, no open pull request title mentions it or tiny-tag-swap, and its bytes overlap nothing in packets #1–#84.

## Scout note

The round-13 scout note listed this window (ranked #3) with FDE `[0x4f7fb20, 0x4f7fb38)`, 24 bytes, 8 padding bytes, zero direct callers, 36 R_X86_64_RELATIVE slots, and nearest claimed window double threshold gate `0x5028a40` (packet #32) `0xa8f20` away. Every element verified exactly, including the full body, the zero incoming sites, and all 36 slot addresses in scout order. No numeric correction to the scout's numbers was needed. One further observation, not a scout deviation since the scout did not claim it: unlike most packets, this window does NOT open with `endbr64`; its first instruction is `cmp $0x2,%sil`.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tiny_tag_swap.py --check research/work-items/foundation-tiny-tag-swap-94/evidence.json
python3 -m unittest tests.test_foundation_tiny_tag_swap -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4f7fb20 --stop-address=0x4f7fb40 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its eight padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2875c4` (this window) and `0x61fb14` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2875c4` describes `[0x4f7fb20, 0x4f7fb38)`, 24 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Eight `int3` bytes follow: the next FDE starts exactly at `0x4f7fb40` (record at `.eh_frame+0x61fb14`, range to `0x4f7fd00`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does NOT open with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x282e0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: tiny tag-swap, no calls, no branches

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | 40 80 fe 02 | cmp $0x2,%sil |
| 0x04 | 0f 94 c0 | sete %al |
| 0x07 | fe c0 | inc %al |
| 0x09 | 31 c9 | xor %ecx,%ecx |
| 0x0b | 40 84 f6 | test %sil,%sil |
| 0x0e | 0f b6 c0 | movzbl %al,%eax |
| 0x11 | 0f 44 c1 | cmove %ecx,%eax |
| 0x14 | 86 47 10 | xchg %al,0x10(%rdi) |
| 0x17 | c3 | ret |

Rule, derived step by step: `sete` sets al to 1 iff sil == 2, else 0; `inc` makes that 2 iff sil == 2, else 1; `cmove` replaces it with 0 iff sil == 0 (the `test` sets ZF exactly then). So the stored byte is 0 when sil == 0, 2 when sil == 2, and 1 for every other input byte. The `xchg` stores that byte at `[rdi+0x10]` and loads the previously stored byte into al, which `ret` returns. The stored value depends only on sil; the returned value is the previous stored byte. The xchg encoding carries no explicit lock prefix; the exchange itself is the distinctive element and is locked exactly as bytes.

No call opcode appears inside the window, and there are no branches at all: the only conditional operations are `sete` and `cmove`, both fall-through.

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: 36 RELATIVE slots, reported as a list

Thirty-six `R_X86_64_RELATIVE` records in `.rela.dyn` name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). They are a pointer table; the checker locks all 36 slot addresses in scan order and the evidence lists them verbatim:

`0x5664220`, `0x566ec28`, `0x567b650`, `0x567bd40`, `0x567ce38`, `0x567e028`, `0x567e988`, `0x567ef98`, `0x5680488`, `0x5680c88`, `0x5681aa8`, `0x5683000`, `0x5683cd8`, `0x5684570`, `0x5684a10`, `0x5685860`, `0x56c97a0`, `0x56ca698`, `0x56cab28`, `0x56cb408`, `0x56cbef0`, `0x56cc050`, `0x56cc140`, `0x56cd2d0`, `0x56ce500`, `0x56ce988`, `0x56cefb8`, `0x56cf848`, `0x56d0398`, `0x56d04c8`, `0x56d1500`, `0x56d2468`, `0x56d35d0`, `0x56d59f8`, `0x56d5b18`, `0x574b088`.

No meaning is claimed for the table they belong to, and the slot list does not identify the window's provenance.

## Inferences

- The "tiny tag-swap" label is an inference from the observed rule: a one-byte store selected by an input tag, returning the previous value. It is kept separate from the rule itself.
- The `[rdi+0x10]` field is plausibly a tag or state byte of some structure, but its owning type is unknown and not claimed.
- The 36-slot pointer table suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the tag values 0, 1, 2 mean, and what reads the stored byte.
- Whether the window is reached via the pointer table, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot list does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
