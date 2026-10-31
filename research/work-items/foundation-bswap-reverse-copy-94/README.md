# foundation-bswap-reverse-copy-94: what does the byte-swapped reversed 4-qword copy window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 43-byte FDE window with five padding bytes, the byte-swapped reversed 4-qword copy rule with its exact fields, the exact incoming-call scan result (two direct sites, each boundary-confirmed in its own caller FDE), and the zero naming-relocation-slot result.
- Excluded: what the structs hold, what the copy is for, what the callers do with the copied data, any wider copy family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a 32-byte copy that reverses both the qword order and the byte order of each qword, with no call inside and a single return. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5632d90`, no open pull request title mentions it or bswap-reverse-copy, and its bytes overlap nothing in packets #1–#112. No bswap packet exists in packets #1–#112.

## Scout note

The round-19 scout note listed this window (ranked #1, cleanest of the round) with FDE `[0x5632d90, 0x5632dbb)`, 43 bytes, 5 padding bytes, zero branches, zero calls inside, 2 direct callers (call sites boundary-confirmed in FDEs `0x563ecc0` and `0x563ff20`), 0 naming slots, and nearest claimed window `0x56544a0` `0x21710` away. Every element verified exactly; no correction was needed.

## Caveats, stated head-on

- **Peer-gap distinction.** The nearest peer PR in this neighbourhood (live #981, the unwindless-boundary PR) covers a code-filled gap ending at `0x5631f00`. This window starts at `0x5632d90`, `0xE90` past that gap end, under its own FDE with its own rule. It is NOT one of the peer's two gap candidates: different location, different FDE, different rule. Nothing here re-claims, re-states, or grades the peer's gap work.
- **Nearest-claimed distinction.** The nearest claimed packet window `0x56544a0` is `0x21710` away, and byte-compare over this window's 43 bytes gives 0/43 identical — different rule, not a twin.
- **Symbol-label disclaimer.** GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it. In particular, no stdlib or private provenance is claimed either way.
- **Caller scale, stated plainly.** Two direct callers is a small, retained fact (both caller FDEs are kept in `caller.objdump.txt`), not a population claim. The byte-pattern scan is not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.
- **Thinness, stated plainly.** This is a single-purpose window: four loads, four byte swaps, four stores, one return. What it is not is ambiguous — the field offsets, the reversal order, and the swap are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bswap_reverse_copy.py --check research/work-items/foundation-bswap-reverse-copy-94/evidence.json
python3 -m unittest tests.test_foundation_bswap_reverse_copy -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5632d90 --stop-address=0x5632dc0 artifacts/node/94/hl-node
objdump -d --start-address=0x563ecc0 --stop-address=0x563ef9f artifacts/node/94/hl-node
objdump -d --start-address=0x563ff20 --stop-address=0x5640295 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its five padding bytes. The `caller.objdump.txt` file retains complete disassembly of both caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2d81c8` (this window), `0x2d81dc` (the next FDE), `0x2d88b4` and `0x2d89e8` (the caller FDEs), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2d81c8` describes `[0x5632d90, 0x5632dbb)`, 43 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Five `int3` bytes follow: the next FDE starts exactly at `0x5632dc0` (record at `.eh_frame+0x2d81dc`, range to `0x5632e7f`). The unwind-index stride is therefore 48 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `mov 0x18(%rsi),%rax`, not `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x5632d90`.

- Offset `0x00`: `mov 0x18(%rsi),%rax` — last source qword load.
- Offset `0x04`: `bswap %rax` — byte order reversed.
- Offset `0x07`: `mov %rax,(%rdi)` — first destination store.
- Offset `0x0a`: `mov 0x10(%rsi),%rax` — third source qword load.
- Offset `0x0e`: `bswap %rax` — byte order reversed.
- Offset `0x11`: `mov %rax,0x8(%rdi)` — second destination store.
- Offset `0x15`: `mov 0x8(%rsi),%rax` — second source qword load.
- Offset `0x19`: `bswap %rax` — byte order reversed.
- Offset `0x1c`: `mov %rax,0x10(%rdi)` — third destination store.
- Offset `0x20`: `mov (%rsi),%rax` — first source qword load.
- Offset `0x23`: `bswap %rax` — byte order reversed.
- Offset `0x26`: `mov %rax,0x18(%rdi)` — fourth destination store.
- Offset `0x2a`: `ret` — single return; zero branches, zero calls inside.

The rule is therefore: `[rdi+0x00] = bswap([rsi+0x18])`, `[rdi+0x08] = bswap([rsi+0x10])`, `[rdi+0x10] = bswap([rsi+0x08])`, `[rdi+0x18] = bswap([rsi+0x00])`. Both the qword order and the byte order of each qword are reversed; the source struct is not modified, and no field outside the 32-byte destination range is written.

### Incoming calls

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` sites whose rel32 lands on the window start: `0x563ed52` and `0x563ff6f`.
- Each site is boundary-confirmed inside its own caller FDE: `0x563ed52` in `[0x563ecc0, 0x563ef9f)`, `0x563ff6f` in `[0x563ff20, 0x5640295)`. Both caller FDEs are retained in full in `caller.objdump.txt`.
- This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.

### Relocation slots

- Full-section scan of `.rela.dyn` (80,022 entries) and `.rela.plt` (278 entries) finds zero `R_X86_64_RELATIVE` records naming this window as addend. The window carries no naming slot; that absence is itself the retained result, and no meaning is claimed from it.

### Byte comparisons

- Nearest claimed packet window `0x56544a0`: 0/43 bytes identical over this window's extent — not a twin, and `0x21710` away.
- No bswap window exists in packets #1–#112, so no closer bswap sibling comparison applies.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere. The "byte-swapped reversed 4-qword copy" label is an inference, kept separate from the observed rule.
- The byte-pattern scan is not a complete xref census, and the absence of a relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
