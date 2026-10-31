# foundation-gated-byte-index-load-94: what does the gated bounded byte-index load window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 104-byte FDE window with 8 padding bytes, the gated byte-index load rule with its exact constants and field offsets, the exact incoming-call scan result (nine direct sites in eight caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the node fields mean, what the indexed bytes represent, any wider byte-load family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a bounded-index byte load — a sentinel byte bypasses the range check, an out-of-range index returns 0, and a clamped cursor offset selects the returned byte, with a fallback byte when cursor == base. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4ff8ac0`, no open pull request title mentions it or gated-byte-index-load, and its bytes overlap nothing in packets #1–#104.

## Scout note

The round-16 scout note listed this window (ranked #3) with FDE `[0x4ff8ac0, 0x4ff8b28)`, 104 bytes, 8 padding bytes, nine direct callers (all boundary-confirmed), no naming relocation, and nearest claimed window double threshold gate `0x5028a40` (packet #32) `0x2ff80` away. Every element verified exactly, with one counting correction stated head-on below.

## Scout correction

The scout note said "nine caller FDEs". The verified count is nine direct `e8` sites in **eight** distinct caller FDEs: two sites (`0x5003a71` and `0x5003e76`) share the FDE `0x5002a30..0x50042bc`. The checker locks all nine sites and all eight FDEs; the "nine FDEs" phrasing is not repeated anywhere as a claim.

## Caller caveat

Nine direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x5002807` (FDE `0x5002330..0x50028cc`), `0x5003a71` and `0x5003e76` (both FDE `0x5002a30..0x50042bc`), `0x5004e91` (FDE `0x5004e70..0x5004ea1`), `0x50207ec` (FDE `0x501fd80..0x5021d92`), `0x5022f05` (FDE `0x5022830..0x502330e`), `0x5023ebe` (FDE `0x5023390..0x50243a7`), `0x5025915` (FDE `0x50244c0..0x5025f76`), and `0x5027fcc` (FDE `0x5026120..0x502890e`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

Shared-caller note, stated head-on: the round-16 ranked #2 window `0x4ff8b30` (gated 48-byte block copy, packet #104, not claimed here) is reached from seven of these eight caller FDEs — the same seven FDEs packet #104 lists, plus this window's extra `0x5004e70..0x5004ea1`. The two windows are used by the same callers but implement different rules over different struct fields (byte load vs 48-byte block copy). No shared primitive is claimed.

Adjacency note, stated head-on: the next FDE `0x4ff8b30` is packet #104's window itself (not an excluded population), and the window sits `0x70` below it in the same region with different struct fields and a different rule. Proximity alone claims nothing.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_gated_byte_index_load.py --check research/work-items/foundation-gated-byte-index-load-94/evidence.json
python3 -m unittest tests.test_foundation_gated_byte_index_load -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4ff8ac0 --stop-address=0x4ff8b30 artifacts/node/94/hl-node
objdump -d --start-address=0x5002330 --stop-address=0x50028cc artifacts/node/94/hl-node
objdump -d --start-address=0x5002a30 --stop-address=0x50042bc artifacts/node/94/hl-node
objdump -d --start-address=0x5004e70 --stop-address=0x5004ea1 artifacts/node/94/hl-node
objdump -d --start-address=0x501fd80 --stop-address=0x5021d92 artifacts/node/94/hl-node
objdump -d --start-address=0x5022830 --stop-address=0x502330e artifacts/node/94/hl-node
objdump -d --start-address=0x5023390 --stop-address=0x50243a7 artifacts/node/94/hl-node
objdump -d --start-address=0x50244c0 --stop-address=0x5025f76 artifacts/node/94/hl-node
objdump -d --start-address=0x5026120 --stop-address=0x502890e artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 8 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the eight caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x28f740` (this window), `0x28f754` (the next FDE), `0x626a5c`, `0x626ac0`, `0x28fdc4`, `0x628588`, `0x628608`, `0x62866c`, `0x6286cc`, and `0x62873c` (the eight caller FDEs), plus the CIE at offset `0` (this window, the next FDE, and the `0x5004e70` caller FDE) and the caller CIE at offset `0x6205d0` (the other seven caller FDEs). The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x28f740` describes `[0x4ff8ac0, 0x4ff8b28)`, 104 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Eight int3 padding bytes follow (`cc` x 8 at `0x4ff8b28..0x4ff8b30`): the next FDE starts exactly at `0x4ff8b30` (record at `.eh_frame+0x28f754`, range to `0x4ff8b9c`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the standard indirect-branch landing pad; that is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x4ff8ac0`. All comparisons are signed 32-bit.

- Offset `0x00`: `endbr64` — indirect-branch landing pad.
- Offset `0x04`: `xor %eax,%eax` — return accumulator zeroed; every early path returns 0 through it.
- Offset `0x06`: `test %r8b,%r8b` — enable-byte test.
- Offset `0x09`: `je 0x4ff8b27` — enable byte 0 returns 0 without reading any struct field.
- Offset `0x0b`: `movzbl 0x154(%rsi),%eax` — sentinel byte load.
- Offset `0x12`: `cmp $0xff,%al` — sentinel compare.
- Offset `0x14`: `je 0x4ff8ae0` — sentinel `0xff` skips the range check and goes straight to the cursor path.
- Offset `0x16`: `mov 0x14(%rdi),%edi` — index field load.
- Offset `0x19`: `sub $0x1,%edi` — index minus one, 32-bit wrapping.
- Offset `0x1c`: `cmp %edx,%edi` — compare the decremented index against the index argument.
- Offset `0x1e`: `jle 0x4ff8b27` — decremented index less than or equal to the index argument (signed) returns 0.
- Offset `0x20`: `mov 0x1d0(%rsi),%rdi` — cursor load.
- Offset `0x27`: `mov 0x1c8(%rsi),%rax` — base load.
- Offset `0x2e`: `cmp %rax,%rdi` — cursor against base.
- Offset `0x31`: `je 0x4ff8b20` — cursor == base takes the fallback byte path.
- Offset `0x33`: `test %edx,%edx` — index zero test.
- Offset `0x35`: `je 0x4ff8b13` — index 0 skips the subtract/clamp steps and loads byte [base].
- Offset `0x37`: `sub %ecx,%edx` — index minus subtrahend, 32-bit wrapping.
- Offset `0x39`: `sub %rax,%rdi` — cursor minus base, 64-bit.
- Offset `0x3c`: `add $0x1,%edx` — index offset plus one.
- Offset `0x3f`: `sub $0x1,%edi` — cursor span minus one.
- Offset `0x42`: `cmp %edi,%edx` — offset against span.
- Offset `0x44`: `cmovg %edi,%edx` — offset clamped down to the span when it exceeds it.
- Offset `0x47`: `movslq %edx,%rcx` — clamped offset sign-extended.
- Offset `0x4a`: `add %rax,%rcx` — base plus clamped offset.
- Offset `0x4d`: `test %edx,%edx` — clamped offset sign test.
- Offset `0x4f`: `cmovg %rcx,%rax` — base-plus-offset selected only when the clamped offset is positive; otherwise `rax` still holds base.
- Offset `0x53`: `movzbl (%rax),%eax` — result byte load.
- Offset `0x56`: `ret` — main return.
- Offset `0x57`: `nopw 0x0(%rax,%rax,1)` — 9-byte intra-body alignment padding between the main return and the fallback block; it is never executed on any path.
- Offset `0x60`: `movzbl 0x153(%rsi),%eax` — fallback byte load (cursor == base path).
- Offset `0x67`: `ret` — fallback return.

All five conditional branches are forward and land inside the window; no branch leaves the window, and no call sits inside it.

### Decoded rule

Let `enable = r8b`, `sentinel = byte [rsi+0x154]`, `field = [rdi+0x14]` signed 32-bit, `index = edx` signed, `sub = ecx` signed, `cursor = [rsi+0x1d0]`, `base = [rsi+0x1c8]`, and `fallback = byte [rsi+0x153]`. The window returns one byte in `eax`:

- `enable == 0` → 0, without reading any struct field.
- `sentinel == 0xff` → cursor path, skipping the range check.
- Otherwise, if `(field - 1) <= index` (signed, 32-bit wrapping subtraction) → 0.
- Cursor path: if `cursor == base` → `fallback`.
- If `index == 0` → byte `[base]`.
- Otherwise: `edx = index - sub + 1`, `edi = cursor - base - 1`, `edx = min(edx, edi)`; if `edx > 0` → byte `[base + edx]`, else byte `[base]`.

No field is written anywhere. Note the asymmetry the bytes force: the range check compares `(field - 1)` against the index argument, while the cursor path reuses that same index argument as the offset input — the checker locks both uses separately and claims no meaning for either.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly nine direct `e8` sites whose rel32 lands on the window start: `0x5002807`, `0x5003a71`, `0x5003e76`, `0x5004e91`, `0x50207ec`, `0x5022f05`, `0x5023ebe`, `0x5025915`, and `0x5027fcc`. Each was confirmed as an instruction start by linear disassembly from its caller FDE start, and all eight caller FDEs are retained in `caller.objdump.txt` with their frame records in `frames.txt`. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation is reported as a scan result only; it does not identify the window's provenance.

### Nearest claimed window

Double threshold gate `0x5028a40` (packet #32) sits `0x2ff80` above this window. The two windows share no field offset, constant, or rule shape: #32 gates on two thresholds, while this window returns a byte selected by an enable byte, a sentinel byte, a signed range check, and a clamped cursor offset. No shared primitive is claimed.

## Inferences

- The "gated bounded byte-index load" label is an inference from the enable/sentinel/range/cursor shape; the window itself names nothing.
- The cursor/base pair at `+0x1d0`/`+0x1c8` looks like an end/start pair bounding a byte range, and the `+0x154`/`+0x153` pair looks like a sentinel byte beside its fallback, but what the range and the bytes are is not claimed.
- The `0xff` sentinel bypass suggests a "no limit" marker, but which value means "no limit" in the caller's domain is not claimed.

## Unknowns

- What the enable byte, the sentinel byte, the index field, the subtrahend, and the cursor/base pair represent, and what the indexed bytes contain.
- Whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- What the nine callers do with the returned byte after the window returns.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
