# foundation-self-link-init-94: what does the self-link init window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 27-byte FDE window with five padding bytes, the self-link init rule with its exact field offsets, the exact incoming-call scan result (zero direct sites), and the 66 relocation slots.
- Excluded: what the node fields mean, what consumes the initialized node, any wider init family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a self-link init that points a node's head pointer at its own +0x10 slot while zeroing both link fields, and returns the base pointer. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4f91ee0`, no open pull request title mentions it or self-link-init, and its bytes overlap nothing in packets #1–#98.

## Scout note

The round-15 scout note listed this window (ranked #3) with FDE `[0x4f91ee0, 0x4f91efb)`, 27 bytes, 5 padding bytes, zero direct callers, R_X86_64_RELATIVE slots from `0x575c6d8` to `0x5777b20`, and nearest claimed window divide-then-log2 bucket `0x4f9eb10` (packet #95) `0xcc30` away. Every element verified exactly except one numeric correction: the slot list has **66** entries, not the scout's 63. The first and last slot addresses match the scout's range; the count was re-derived twice (a section-aware relocation scan and a direct readelf grep both give 66, all R_X86_64_RELATIVE in `.rela.dyn`). The corrected 66-slot list is what the checker locks.

## Struct-init distinction

This window is NOT the excluded lea-vtable struct-init shape, and the bytes are why: the excluded shape loads a vtable address from `.rodata` with a rip-relative `lea` and stores it into a struct field. This window contains no rip-relative load at all. Its only `lea` computes `rdi+0x10` — a self-pointer derived from the base argument, not an address from a table — and the remaining stores are immediates (0 into `[rdi+8]`, 0 into the byte at `[rdi+0x10]`). A self-referential init with no vtable reference is a different shape from a vtable-carrying struct init, and it is claimed only as that.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_self_link_init.py --check research/work-items/foundation-self-link-init-94/evidence.json
python3 -m unittest tests.test_foundation_self_link_init -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4f91ee0 --stop-address=0x4f91f00 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its five padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x28987c` (this window) and `0x289890` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x28987c` describes `[0x4f91ee0, 0x4f91efb)`, 27 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Five `int3` bytes follow: the next FDE starts exactly at `0x4f91f00` (record at `.eh_frame+0x289890`, range to `0x4f9200c`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x15f20`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: self-link init, no branches, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8d 57 10 | lea 0x10(%rdi),%rdx |
| 0x08 | 48 c7 47 08 00 00 00 00 | movq $0x0,0x8(%rdi) |
| 0x10 | 48 89 f8 | mov %rdi,%rax |
| 0x13 | 48 89 17 | mov %rdx,(%rdi) |
| 0x16 | c6 47 10 00 | movb $0x0,0x10(%rdi) |
| 0x1a | c3 | ret |

Rule, derived step by step: `rdx` is set to `rdi+0x10`; the qword at `[rdi+8]` is zeroed; `rax` is set to `rdi`; the head pointer `[rdi]` is set to `rdx`, i.e. to the node's own +0x10 slot; the byte at `[rdi+0x10]` is zeroed; `ret` returns `rax`, i.e. `rdi`. No branch opcode and no call opcode appears inside the window, and the only stores are the three listed ones. The byte at `[rdi+0x10]` is the first byte of the slot the head pointer now points at; whether that slot is a link field, a tag, or something else is not claimed — only that the byte is zeroed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on `0x4f91ee0`. That is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.

### Data edges

Sixty-six `R_X86_64_RELATIVE` records in `.rela.dyn` name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). They are reported as a slot list only, in the same treatment as packet #85's 36 slots: a pointer-table slot list whose table's meaning is not claimed. The first slot is `0x575c6d8`, the last is `0x5777b20`.

## Inferences

- The "self-link init" label is an inference from the observed stores: a head pointer that points at the node's own +0x10 slot, with the neighboring link qword and the slot's first byte zeroed, reads as initialization of a self-referential node. The label is kept separate from the rule.
- The 66-slot pointer table suggests many static sites reference this window, but no table purpose, element type, or owner is inferred from the slot list alone.

## Unknowns

- What the fields at `[rdi]`, `[rdi+8]`, and `[rdi+0x10]` mean, and what structure `rdi` points at.
- What consumes the initialized node, and whether the zeroed byte at `[rdi+0x10]` is a link field, a flag, or a tag.
- Whether the 66 relocation slots belong to one table or several, and what the table is for.
- Which source-level function, if any, this window corresponds to.

## Limits

- No stdlib type, source-level function, field meaning, or consumer is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
