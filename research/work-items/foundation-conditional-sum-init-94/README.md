# foundation-conditional-sum-init-94: what does the conditional-sum init window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 45-byte FDE window with 3 padding bytes, the conditional-sum init rule with its exact constants and field offsets, the exact incoming-call scan result (two direct sites in two caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the node fields mean, what the struct represents, any wider init family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a small init that zeroes two struct fields, stores a sign-extended input into a third, and stores a conditional sum into a fourth, returning 1. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5475e80`, no open pull request title mentions it or conditional-sum-init, and its bytes overlap nothing in packets #1–#106.

## Scout note

The round-16 scout note listed this window (backup B1, the first backup after ranked #1–#4) with FDE `[0x5475e80, 0x5475ead)`, 45 bytes, 3 padding bytes, two direct callers (both boundary-confirmed), no naming relocation, and nearest claimed window bit-writer drain `0x5494050` (packet #84) `0x1e1d0` away. Every scouted element verified exactly. One note on the parent brief (not the scout note): the brief's rule sketch listed three stores and omitted the `[rdi + 0x10] = 0` store; the scout note listed it, and the retained bytes confirm four stores. That fourth store is locked by the checker below.

## Caller caveat

Two direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x5010b7f` (FDE `0x50107c0..0x50118e5`) and `0x53cc23c` (FDE `0x53cb9e0..0x53cc9f1`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

## Init-adjacent caveat, stated head-on

This window is plainly init-adjacent: four field stores, one of them conditional. What distinguishes it from a plain struct init is the conditional computed field — `[rdi + 8]` holds `sext(edx) + rsi` only when `edx != 0`, and the unmodified `rsi` otherwise — plus the constant return value 1. What is claimed is narrow: the exact behavior of this one complete FDE window (no calls inside, no branch leaving it, a single ret on the only path), with no claim about the struct, its consumers, or what the stored values mean.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_conditional_sum_init.py --check research/work-items/foundation-conditional-sum-init-94/evidence.json
python3 -m unittest tests.test_foundation_conditional_sum_init -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5475e80 --stop-address=0x5475eb0 artifacts/node/94/hl-node
objdump -d --start-address=0x50107c0 --stop-address=0x50118e5 artifacts/node/94/hl-node
objdump -d --start-address=0x53cb9e0 --stop-address=0x53cc9f1 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 3 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the two caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2be74c` (this window), `0x2be760` (the next FDE), `0x62735c` and `0x657ddc` (the two caller FDEs), plus the CIE at offset `0` (this window and the next FDE) and the CIE at offset `0x6205d0` (both caller FDEs). The checker locks these raw FDE records and both CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2be74c` describes `[0x5475e80, 0x5475ead)`, 45 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Three int3 padding bytes follow (`cc` x 3 at `0x5475ead..0x5475eb0`): the next FDE starts exactly at `0x5475eb0` (record at `.eh_frame+0x2be760`, range to `0x54770a1`). The unwind-index stride is therefore 48 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the standard indirect-branch landing pad; that is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x5475e80`. The input is sign-extended by `movslq` (not zero-extended); the conditional sum wraps at 64 bits.

- Offset `0x00`: `endbr64` — indirect-branch landing pad.
- Offset `0x04`: `movslq %edx,%rax` — input sign-extended into rax.
- Offset `0x07`: `movq $0x0,(%rdi)` — first field zeroed.
- Offset `0x0e`: `mov %rax,0x18(%rdi)` — sign-extended input stored.
- Offset `0x12`: `add %rsi,%rax` — candidate sum formed unconditionally.
- Offset `0x15`: `test %edx,%edx` — zero-input test on the original 32-bit input.
- Offset `0x17`: `cmovne %rax,%rsi` — nonzero input replaces rsi with the sum; zero input keeps the original rsi.
- Offset `0x1b`: `movq $0x0,0x10(%rdi)` — second field zeroed.
- Offset `0x23`: `mov $0x1,%eax` — constant return value 1.
- Offset `0x28`: `mov %rsi,0x8(%rdi)` — conditional sum (or original rsi) stored.
- Offset `0x2c`: `ret` — single return; no other exit exists.

### Decoded rule

On the only path, with `edx` the raw 32-bit input and `rsi` the 64-bit addend:

- `[rdi] = 0`, `[rdi + 0x10] = 0` — two fields zeroed unconditionally.
- `[rdi + 0x18] = sext32(edx)` — the sign-extended input, stored unconditionally.
- `[rdi + 8] = (edx != 0) ? sext32(edx) + rsi : rsi` — the conditional sum, wrapping at 64 bits.
- Return value: `eax = 1`.

Rule edges, hand-computed from the retained bytes (not execution):

- `edx = 0, rsi = 0x1000` → `[rdi + 8] = 0x1000`, `[rdi + 0x18] = 0`, return 1.
- `edx = 5, rsi = 0x1000` → `[rdi + 8] = 0x1005`, `[rdi + 0x18] = 5`, return 1.
- `edx = 0xffffffff` (i.e. -1), `rsi = 0x1000` → `[rdi + 8] = 0xfff`, `[rdi + 0x18] = 0xffffffffffffffff`, return 1.
- `edx = 0x80000000` (i.e. -2147483648), `rsi = 0x1000` → `[rdi + 8] = 0xffffffff80001000`, `[rdi + 0x18] = 0xffffffff80000000`, return 1.

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` sites landing on the window start: `0x5010b7f` and `0x53cc23c`, each confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census.
- No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The window is reported with zero naming slots; no provenance is inferred from that absence.
- Nearest claimed window: bit-writer drain `0x5494050` (packet #84), `0x1e1d0` away. No shared primitive is claimed.

## Inferences (kept separate from observations)

- The label "conditional-sum init" is an inference from the four-store shape plus the constant return; the bytes alone establish only the store pattern and the return constant.
- The return value 1 may be a success code, a boolean, or a count; the bytes do not say, and no meaning is claimed.
- The two zeroed fields and the two written fields may belong to one struct or to adjacent objects; the bytes show only that all four offsets share the same `rdi` base.

## Unknowns

- What the struct at `rdi` is, what its fields mean, and what consumes the stored values.
- Whether the two callers pass related inputs or use the window for different purposes; no caller purpose is claimed.
- Whether any indirect call, tail jump, or PLT reference reaches this window; the byte-pattern scan does not cover those.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
