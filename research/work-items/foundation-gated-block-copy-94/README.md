# foundation-gated-block-copy-94: what does the gated 48-byte block copy window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 108-byte FDE window with 4 padding bytes, the gated block-copy rule with its exact constants and field offsets, the exact incoming-call scan result (eight direct sites, all in seven caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the node fields mean, what the copied blocks represent, any wider block-copy family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a three-gate block copy — a flag byte, a signed index-range check, and a gate byte jointly select between two 48-byte source blocks. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4ff8b30`, no open pull request title mentions it or gated-block-copy, and its bytes overlap nothing in packets #1–#103.

## Scout note

The round-16 scout note listed this window (ranked #2, the richest rule this round) with FDE `[0x4ff8b30, 0x4ff8b9c)`, 108 bytes, 4 padding bytes, eight direct callers (all boundary-confirmed), no naming relocation, and nearest claimed window double threshold gate `0x5028a40` (packet #32) `0x2ff10` away. Every element verified exactly; no scout correction was needed.

## Caller caveat

Eight direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x50023f8` (FDE `0x5002330..0x50028cc`), `0x5003a54` and `0x5003e5b` (both FDE `0x5002a30..0x50042bc`), `0x50207c7` (FDE `0x501fd80..0x5021d92`), `0x5022eeb` (FDE `0x5022830..0x502330e`), `0x5023e9f` (FDE `0x5023390..0x50243a7`), `0x50258f1` (FDE `0x50244c0..0x5025f76`), and `0x5027fae` (FDE `0x5026120..0x502890e`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

Shared-caller note, stated head-on: the round-16 ranked #3 window `0x4ff8ac0` (gated bounded byte-index load, not claimed here) is reached from the same seven caller FDEs — verified by scanning its own nine direct `e8` sites, which map to those seven FDEs plus one more (`0x5004e70..0x5004ea1`). The two windows are used by the same callers but implement different rules over different struct fields (byte load vs 48-byte block copy). No shared primitive is claimed.

Adjacency note, stated head-on: the next FDE `0x4ff8ba0` is a lea-vtable struct-init (excluded population, not claimed), and ranked #3 `0x4ff8ac0` sits `0x70` below this window in the same region with different struct fields and a different rule. Proximity alone claims nothing.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_gated_block_copy.py --check research/work-items/foundation-gated-block-copy-94/evidence.json
python3 -m unittest tests.test_foundation_gated_block_copy -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4ff8b30 --stop-address=0x4ff8ba0 artifacts/node/94/hl-node
objdump -d --start-address=0x5002330 --stop-address=0x50028cc artifacts/node/94/hl-node
objdump -d --start-address=0x5002a30 --stop-address=0x50042bc artifacts/node/94/hl-node
objdump -d --start-address=0x501fd80 --stop-address=0x5021d92 artifacts/node/94/hl-node
objdump -d --start-address=0x5022830 --stop-address=0x502330e artifacts/node/94/hl-node
objdump -d --start-address=0x5023390 --stop-address=0x50243a7 artifacts/node/94/hl-node
objdump -d --start-address=0x50244c0 --stop-address=0x5025f76 artifacts/node/94/hl-node
objdump -d --start-address=0x5026120 --stop-address=0x502890e artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 4 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the seven caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x28f754` (this window), `0x28f768` (the next FDE), `0x626a5c`, `0x626ac0`, `0x628588`, `0x628608`, `0x62866c`, `0x6286cc`, and `0x62873c` (the seven caller FDEs), plus the CIE at offset `0` (this window and the next FDE) and the caller CIE at offset `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x28f754` describes `[0x4ff8b30, 0x4ff8b9c)`, 108 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Four int3 padding bytes follow (`cc cc cc cc` at `0x4ff8b9c..0x4ff8ba0`): the next FDE starts exactly at `0x4ff8ba0` (record at `.eh_frame+0x28f768`, range to `0x4ff8c15`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the standard indirect-branch landing pad; that is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x4ff8b30`. All comparisons are signed 32-bit.

- Offset `0x00`: `endbr64` — indirect-branch landing pad.
- Offset `0x04`: `mov %rdi,%rax` — destination pointer copied; path B stores through `rax`, path A through `rdi`, so both paths write the same destination.
- Offset `0x07`: `test %r8b,%r8b` — flag-byte test.
- Offset `0x0a`: `je 0x4ff8b78` — flag byte 0 selects path B.
- Offset `0x0c`: `mov 0x14(%rdx),%edx` — index field load.
- Offset `0x0f`: `sub $0x1,%edx` — index minus one, 32-bit wrapping.
- Offset `0x12`: `cmp %ecx,%edx` — compare the decremented index against the bound.
- Offset `0x14`: `jg 0x4ff8b78` — decremented index strictly greater than the bound selects path B.
- Offset `0x16`: `cmpb $0x0,0x1a0(%rsi)` — gate-byte test.
- Offset `0x1d`: `je 0x4ff8b78` — gate byte 0 selects path B.
- Offset `0x1f`: `movdqu 0x188(%rsi),%xmm3` — path A, first 16 bytes.
- Offset `0x27`: `movdqu 0x198(%rsi),%xmm4` — path A, second 16 bytes.
- Offset `0x2f`: `movdqu 0x1a8(%rsi),%xmm5` — path A, third 16 bytes.
- Offset `0x37`: `movups %xmm3,(%rdi)` — path A store, bytes 0..16.
- Offset `0x3a`: `movups %xmm4,0x10(%rdi)` — path A store, bytes 16..32.
- Offset `0x3e`: `movups %xmm5,0x20(%rdi)` — path A store, bytes 32..48.
- Offset `0x42`: `ret` — path A return.
- Offset `0x43`: `nopl 0x0(%rax,%rax,1)` — 5-byte intra-body alignment padding between the path-A return and the path-B block; it is never executed on either path.
- Offset `0x48`: `movdqu 0x158(%rsi),%xmm0` — path B, first 16 bytes.
- Offset `0x50`: `movdqu 0x168(%rsi),%xmm1` — path B, second 16 bytes.
- Offset `0x58`: `movdqu 0x178(%rsi),%xmm2` — path B, third 16 bytes.
- Offset `0x60`: `movups %xmm0,(%rax)` — path B store, bytes 0..16.
- Offset `0x63`: `movups %xmm1,0x10(%rax)` — path B store, bytes 16..32.
- Offset `0x67`: `movups %xmm2,0x20(%rax)` — path B store, bytes 32..48.
- Offset `0x6b`: `ret` — path B return.

All three conditional branches are forward and land on the same path-B block at `0x4ff8b78`; no branch leaves the window, and no call sits inside it.

### Decoded rule

Let `flag = r8b`, `field = [rdx+0x14]` as a signed 32-bit value, `bound = ecx` signed, and `gate = byte [rsi+0x1a0]`. The destination receives 48 bytes:

- Path A (source block at `[rsi+0x188 .. rsi+0x1b8)`), exactly when all three gates pass: `flag != 0`, `(field - 1) <= bound` (signed, 32-bit wrapping subtraction), and `gate != 0`.
- Path B (source block at `[rsi+0x158 .. rsi+0x188)`), otherwise: `flag == 0`, or `(field - 1) > bound`, or `gate == 0`.

No field besides the 48 destination bytes is written. The two source blocks are adjacent and non-overlapping; path A's block starts exactly where path B's block ends. No return value is claimed: on exit `rax` still holds `rdi`, but the packet claims only the destination write.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly eight direct `e8` sites whose rel32 lands on the window start: `0x50023f8`, `0x5003a54`, `0x5003e5b`, `0x50207c7`, `0x5022eeb`, `0x5023e9f`, `0x50258f1`, and `0x5027fae`. Each was confirmed as an instruction start by linear disassembly from its caller FDE start, and all seven caller FDEs are retained in `caller.objdump.txt` with their frame records in `frames.txt`. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation is reported as a scan result only; it does not identify the window's provenance.

### Nearest claimed window

Double threshold gate `0x5028a40` (packet #32) sits `0x2ff10` above this window. The two windows share no field offset, constant, or rule shape: #32 gates on two thresholds, while this window selects between two 48-byte blocks with a flag byte, an index-range check, and a gate byte. No shared primitive is claimed.

## Inferences

- The "gated block copy" label is an inference from the three-gate, two-block shape; the window itself names nothing.
- The adjacent source blocks (path B at `+0x158`, path A at `+0x188`) look like two variants of one 48-byte record selected by the gates, but what the record is is not claimed.
- The flag byte plus index-range plus gate-byte shape suggests a fallback/default selection, but which block is the default is not claimed.

## Unknowns

- What the index field, the bound, the flag byte, and the gate byte represent, and what the copied blocks contain.
- Whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- What the seven callers do with the copied block after the window returns.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
