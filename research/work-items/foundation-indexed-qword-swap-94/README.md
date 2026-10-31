# foundation-indexed-qword-swap-94: what does the indexed qword swap window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 105-byte FDE window with seven padding bytes, the indexed qword swap rule with its exact field offsets and threshold, the exact incoming-call scan result (four direct sites, all in one caller FDE), and the zero-naming-relocation result.
- Excluded: what the node fields mean, what the swapped values represent, any wider swap family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: two element pointers computed from two base structs through a threshold-split table base, with the qwords at those pointers swapped. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4fa90a0`, no open pull request title mentions it or indexed-qword-swap, and its bytes overlap nothing in packets #1–#100.

## Scout note

The round-15 scout note listed this window (backup B1, the first backup item after the ranked four) with FDE `[0x4fa90a0, 0x4fa9109)`, 105 bytes, 7 padding bytes, four direct callers all in one caller FDE (`0x4fabb90..0x4fac29f`: `0x4fabc77`, `0x4fac161`, `0x4fac199`, `0x4fac1da`), no naming relocation, and nearest claimed window divide-then-log2 bucket `0x4f9eb10` (packet #95) `0xa590` away. Every element verified exactly; no scout correction was needed.

## Shared-caller caveat

All four direct call sites sit in a single caller FDE (`0x4fabb90..0x4fac29f`), so they are four call sites, not four independent callers — the same caveat packet #84 stated for its shared-caller helper. Each site was confirmed as an instruction start by linear disassembly from the caller FDE start, and the caller FDE is retained whole in `caller.objdump.txt`. No caller purpose is claimed, and the byte-pattern scan is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

## Packet #75 distinction

Packet #75's index-clamp-stride helper also takes indices and emits pointers, but it clamps indices into range and returns pointers without touching memory. This window never clamps — indices above `0x1f` take a different table base — and it writes: it swaps the two qwords at the computed pointers. Clamp-and-emit vs threshold-split-and-swap; no shared primitive is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_indexed_qword_swap.py --check research/work-items/foundation-indexed-qword-swap-94/evidence.json
python3 -m unittest tests.test_foundation_indexed_qword_swap -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4fa90a0 --stop-address=0x4fa9110 artifacts/node/94/hl-node
objdump -d --start-address=0x4fabb90 --stop-address=0x4fac29f artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its seven padding bytes. The `caller.objdump.txt` file retains complete disassembly of the single caller FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x28bba4` (this window), `0x28bbb8` (the next FDE), and `0x28c294` (the caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x28bba4` describes `[0x4fa90a0, 0x4fa9109)`, 105 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Seven `int3` bytes follow: the next FDE starts exactly at `0x4fa9110` (record at `.eh_frame+0x28bbb8`, range to `0x4fa91a2`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does **not** open with `endbr64`: it opens directly with `cmp $0x1f,%rcx`. That is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x4fa90a0`. All loads and stores are 64-bit qwords; all arithmetic wraps at 64 bits.

- Offset `0x00`: `cmp $0x1f,%rcx` — unsigned threshold test on the first index.
- Offset `0x04`: `jbe 0x4fa90e0` (2 bytes, disp `0x3a`) — first index `<= 0x1f` takes the low-first block.
- Offset `0x06`: `mov 0x110(%rdx),%rax` — high first table base.
- Offset `0x0d`: `lea -0x100(%rax,%rcx,8),%rax` — first pointer = high base + (`rcx` − `0x20`) * 8. The displacement is part of the instruction encoding (`00 ff ff ff`); objdump wraps the final `ff` byte onto its own display line, but the instruction is 8 bytes ending at offset `0x15`.
- Offset `0x15`: `cmp $0x1f,%rsi` — unsigned threshold test on the second index.
- Offset `0x19`: `jbe 0x4fa90f1` (2 bytes, disp `0x36`) — second index `<= 0x1f` takes the low-second block.
- Offset `0x1b`: `mov 0x110(%rdi),%rdx` — high second table base.
- Offset `0x22`: `lea -0x100(%rdx,%rsi,8),%rdx` — second pointer = high base + (`rsi` − `0x20`) * 8 (same display-wrap note: 8 bytes ending at offset `0x2a`).
- Offset `0x2a`: `mov (%rax),%rsi`; offset `0x2d`: `mov (%rdx),%rcx`; offset `0x30`: `mov %rsi,(%rdx)`; offset `0x33`: `mov %rcx,(%rax)`; offset `0x36`: `ret` — the swap block: the two qwords exchange places.
- Offset `0x37`: `nopw 0x0(%rax,%rax,1)` (9 bytes) — intra-body alignment padding between the two swap blocks.
- Offset `0x40`: `mov 0x108(%rdx),%rax`; offset `0x47`: `lea (%rax,%rcx,8),%rax` — low first pointer = low base + `rcx` * 8.
- Offset `0x4b`: `cmp $0x1f,%rsi`; offset `0x4f`: `ja 0x4fa90bb` (2 bytes, disp `0xca` = −54) — second index `> 0x1f` re-enters the high-second block above.
- Offset `0x51`: `mov 0x108(%rdi),%rdx`; offset `0x58`: `lea (%rdx,%rsi,8),%rdx` — low second pointer = low base + `rsi` * 8.
- Offset `0x5c`–`0x68`: the identical swap block again (`mov (%rax),%rsi`; `mov (%rdx),%rcx`; `mov %rsi,(%rdx)`; `mov %rcx,(%rax)`; `ret`).

### Decoded rule

For a base struct `S` and an index `i` (unsigned):

- if `i <= 0x1f`: pointer = `[S+0x108] + i * 8`;
- else: pointer = `[S+0x110] + (i - 0x20) * 8`.

The window computes the first pointer from struct `rdx` and index `rcx`, the second pointer from struct `rdi` and index `rsi`, then swaps the qwords at the two pointers. No other field is written, and no return value is claimed: on exit `rax` holds the first pointer and `rdx` the second, with `rcx`/`rsi` holding the swapped values. The two table-base fields (`+0x108`, `+0x110`) are themselves pointers loaded from the structs; whether the two bases point at adjacent memory is not claimed — only the selection rule above.

The control flow is a four-way dispatch (low/low, low/high, high/low, high/high) converging on two identical swap blocks, with three conditional branches and no loop: every path falls through to a `ret`.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly four direct `e8` sites whose rel32 lands on the window start: `0x4fabc77` (bytes `e8 24 d4 ff ff`), `0x4fac161` (`e8 3a cf ff ff`), `0x4fac199` (`e8 02 cf ff ff`), `0x4fac1da` (`e8 c1 ce ff ff`). Each was confirmed as an instruction start by linear disassembly from the caller FDE start `0x4fabb90`, and all four sit in that one caller FDE (`[0x4fabb90, 0x4fac29f)`). This is explicitly not a complete xref census.

### Data edges

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The label "indexed qword swap with threshold-split table base" is an inference from the observed rule; the rule itself is the observation.
- The two structs are treated symmetrically (same field offsets, same threshold), but nothing is claimed about whether they are the same type.
- The swapped qwords' meaning, the indices' source, and the caller FDE's purpose are not inferred.

## Unknowns

- No source-level function, type, or field meaning is claimed anywhere.
- No claim is made about which callers beyond the four direct sites exist (indirect calls and tail jumps are out of scope for the scan).
- No claim is made about whether the two table bases ever alias or overlap.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
