# foundation-byte-dword-gate-94: what does the byte/dword gate window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 26-byte FDE window with six padding bytes, the byte/dword gate rule it implements, the exact incoming-call scan result (three direct sites in three caller FDEs), the incoming tail jump from the address-order next window, and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the callers, the purpose of the neighbor window's jump into this window, and any wider gate family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a nonzero flag byte with a positive count short-circuits with the byte itself; otherwise a signed dword comparison decides. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5172c70`, no open pull request title mentions it or byte-dword-gate, and its bytes overlap nothing in packets #1–#77.

## Scout note

The round-12 scout note listed this window (ranked #1, the cleanest item this round) with FDE `[0x5172c70, 0x5172c8a)`, 26 bytes, 6 padding bytes, three direct callers all boundary-confirmed, no naming relocation, and the neighbor `0x5172c90` tail-jumping into it. Every element verified exactly, including the neighbor's `jmp 0x5172c70` at `0x5172cb0`. No numeric correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the three direct sites are incoming calls from three caller FDEs — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_dword_gate.py --check research/work-items/foundation-byte-dword-gate-94/evidence.json
python3 -m unittest tests.test_foundation_byte_dword_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5172c70 --stop-address=0x5172c90 artifacts/node/94/hl-node
objdump -d --start-address=0x503a7f0 --stop-address=0x503ab70 artifacts/node/94/hl-node
objdump -d --start-address=0x5047bd0 --stop-address=0x50493b4 artifacts/node/94/hl-node
objdump -d --start-address=0x514ae30 --stop-address=0x514ae58 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its six padding bytes. The `caller.objdump.txt` file retains complete disassembly of all three caller FDEs, from which the three call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c460` (this window), `0x29c474` (the next FDE, which is the neighbor window), `0x6297dc`, `0x629df4`, `0x29a274` (the three caller FDEs), plus the shared CIEs at offsets `0` and `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c460` describes `[0x5172c70, 0x5172c8a)`, 26 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Six `int3` bytes (`0xcc`) follow at `0x5172c8a`–`0x5172c8f`, and the next FDE starts exactly at `0x5172c90` (record at `.eh_frame+0x29c474`, range to `0x5172cb5`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x1cae70`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: byte/dword gate, no calls, two forward branches

Inputs: `rdi` = struct pointer. Fields read: flag byte at `[rdi+0x15]`, count dword at `[rdi+0x10]`, compared dword at `[rdi+0x4]`. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5172c70` | `endbr64` | Landing pad |
| `0x5172c74` | `movzbl 0x15(%rdi),%eax` | Flag byte loaded, zero-extended |
| `0x5172c78` | `mov 0x10(%rdi),%edx` | Count dword loaded |
| `0x5172c7b` | `test %al,%al` | Flag-zero test |
| `0x5172c7d` | `je 0x5172c83` | Flag zero → dword comparison |
| `0x5172c7f` | `test %edx,%edx` | Count-sign test |
| `0x5172c81` | `jg 0x5172c89` | Count positive → return the byte |
| `0x5172c83` | `cmp %edx,0x4(%rdi)` | Computes `[rdi+0x4] - count` |
| `0x5172c86` | `setle %al` | 1 iff `[rdi+0x4] <= count` (signed) |
| `0x5172c89` | `ret` | |

Rule: if the flag byte is nonzero AND the count dword is positive (signed), return the flag byte. Otherwise return 1 iff dword `[rdi+0x4] <= dword [rdi+0x10]` (signed), else 0. Both comparisons are signed 32-bit: the count gate uses `test` + `jg`, and the fallback uses `cmp` + `setle`. The `movzbl` zero-extends, so the returned byte is 0..255 and the `setle` low byte is the whole return value — no stale-high-byte caveat on either path, because the fallback path overwrites `al` and the short-circuit path returns with `eax` still holding the zero-extended byte.

Worked edges: byte 5, count 3 → 5 (the dword comparison is never reached); byte 5, count 0 → dword comparison decides; byte 5, count −1 → dword comparison decides (the count gate is signed); byte 0, count 3, `[rdi+0x4]` 1 vs count 3 → 1; byte 0, count 3, 5 vs 3 → 0; byte 0, count 3, 3 vs 3 → 1 (equality included); byte 0xff, count 1 → 255; byte 0, count 1, `[rdi+0x4]` −1 vs count 0 → 1 (signed, not unsigned).

### Incoming calls: three direct sites, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` sites whose rel32 lands on the window start — explicitly not a complete xref census (indirect calls, tail jumps, and PLT references are out of scope):

| Call site | Caller FDE | Setup immediately before the call |
| --- | --- | --- |
| `0x503a9b7` | `0x503a7f0..0x503ab70` | `lea 0x8f0(%rbp),%rdi` |
| `0x5047fde` | `0x5047bd0..0x50493b4` | `lea 0x8f0(%r12),%rdi` |
| `0x514ae46` | `0x514ae30..0x514ae58` | `add $0x8f0,%rdi` |

Each site was confirmed as an instruction start by linear disassembly from its caller FDE start. All three setups compute the struct pointer as a base plus `0x8f0`; that shared offset is locked as bytes, and no caller purpose is claimed from it.

### Incoming tail jump from the neighbor window

The address-order next window `0x5172c90` (FDE `[0x5172c90, 0x5172cb5)`, which is also the next record in `.eh_frame` order at `0x29c474`) ends with `jmp 0x5172c70` at `0x5172cb0` (bytes `e9 bb ff ff ff`). That is an incoming tail jump into this window, not a call: the neighbor's fall-through path returns or jumps elsewhere, and only its equal-branch path reaches this window's start. The neighbor window itself is not built here, and no claim is made about why it jumps here. The checker locks the five jump bytes and their computed target.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

### Nearest claimed window

The nearest claimed window is the tiny two-byte gate `0x51647b0` (packet #72), `0xe4c0` away — outside the scout's `0x2000` exclusion radius around claimed windows.

## Inferences (kept separate from observations)

- The "byte/dword gate" label is an inference from the observed rule, not a source-level name.
- The three fields are called "flag byte", "count", and "compared dword" only by their roles in the branches; their struct meaning is unknown.
- The shared `0x8f0` offset in all three caller setups suggests the callers pass the same kind of struct, but that is a suggestion only — no caller identity or shared-primitive claim follows from it.

## Unknowns

- What the struct is, what the fields mean, and what the callers do with the returned byte.
- Why the neighbor window jumps into this window on one path.
- Whether any indirect caller or PLT reference reaches this window (outside the scan's scope).
- The source-level function, type, or component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
