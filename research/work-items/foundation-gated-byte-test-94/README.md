# foundation-gated-byte-test-94: what does the gated byte test window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 27-byte FDE window with five padding bytes, the gated byte test rule with its exact field offsets and branch target, the exact incoming-call scan result (zero direct sites), and the two relocation slots.
- Excluded: what the pointer field and the gate byte mean, what reads the returned byte, any wider gate-test family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a gated byte test that returns 0 when its pointer field is null, and otherwise returns 1 exactly when its gate byte is clear. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x53d1f90`, no open pull request title mentions it or gated-byte-test, and its bytes overlap nothing in packets #1–#96.

## Scout note

The round-15 scout note listed this window (ranked #1) with FDE `[0x53d1f90, 0x53d1fab)`, 27 bytes, 5 padding bytes, zero direct callers, two R_X86_64_RELATIVE slots (`0x5764f50`, `0x5778c30`), and nearest claimed window gated two-field copy `0x53b1120` (packet #93) `0x20e70` away. Every element verified exactly, including the full body, the branch target, the zero incoming sites, and both slot addresses. No numeric correction to the scout's numbers was needed.

## Shared-offset caveat

Packet #93's gated two-field copy also gates on the byte at `[rdi+0xb8]`, but with a different rule and a different struct: #93 loads its pointer from `[rdi+0x2d8]` and copies two qwords from `[p+0x20]` and `[p+0x60]` into `[rsi+0x10]` and `[rsi+0x18]`, while this window tests the qword at `[rdi+0xb0]` and returns a byte, writing nothing. The shared offset is stated head-on; no shared primitive is claimed.

## Pair-mate caveat

The immediately following FDE, `[0x53d1fb0, 0x53d1fc4)`, loads `p = [rdi+0xb0]` and returns the pair `([p+0x10], [p+0x8])` — a two-hop pair load sharing this window's pointer field. That window is a pair mate with this one, and it is NOT claimed here: this packet binds only `0x53d1f90`, so the pair is not double-claimed. The pair window's rule is described here only to mark the boundary.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_gated_byte_test.py --check research/work-items/foundation-gated-byte-test-94/evidence.json
python3 -m unittest tests.test_foundation_gated_byte_test -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53d1f90 --stop-address=0x53d1fb0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its five padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b6948` (this window) and `0x2b695c` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b6948` describes `[0x53d1f90, 0x53d1fab)`, 27 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Five `int3` bytes follow: the next FDE starts exactly at `0x53d1fb0` (record at `.eh_frame+0x2b695c`, range to `0x53d1fc4`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x42a190`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: gated byte test, one branch, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 31 c0 | xor %eax,%eax |
| 0x06 | 48 83 bf b0 00 00 00 00 | cmpq $0x0,0xb0(%rdi) |
| 0x0e | 74 0a | je 0x53d1faa |
| 0x10 | 80 bf b8 00 00 00 00 | cmpb $0x0,0xb8(%rdi) |
| 0x17 | 0f 94 c0 | sete %al |
| 0x1a | c3 | ret |

Rule, derived step by step: eax is zeroed first; the compare tests the qword field `[rdi+0xb0]` against zero; the branch jumps to `ret` when it is zero, so the null path returns 0 without ever reading the gate byte. Otherwise the compare tests the gate byte `[rdi+0xb8]` against zero, and `sete` writes 1 into %al exactly when it is zero, else 0. Because eax was zeroed first, the upper bytes of eax are 0 on every path, so the returned eax is a clean boolean: 0 when the pointer field is null, else 1 iff the gate byte is clear. The branch target is exact: the `je` at offset `0x0e` is 2 bytes with displacement `0x0a`, landing on the `ret` at offset `0x1a` (`0x53d1faa`). No call opcode appears inside the window, and no field is written.

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: two RELATIVE slots, reported as a list

Two `R_X86_64_RELATIVE` records in `.rela.dyn` name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries):

`0x5764f50`, `0x5778c30`.

No meaning is claimed for the table they belong to, and the slot list does not identify the window's provenance.

## Inferences

- The "gated byte test" label is an inference from the observed rule: a null check plus a gate byte test returning a byte. It is kept separate from the rule itself.
- The pointer field and the gate byte are plausibly fields of some structure, but their owning type is unknown and not claimed.
- The two relocation slots suggest the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the pointer field and the gate byte mean, and what reads the returned byte.
- Whether the window is reached via one of the relocation slots, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slots do not identify the window's provenance.
- The adjacent pair window `0x53d1fb0` is not claimed by this packet.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
