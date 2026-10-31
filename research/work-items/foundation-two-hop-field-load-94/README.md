# foundation-two-hop-field-load-94: what does the two-hop field load window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 39-byte FDE window with nine padding bytes, the two-hop field load rule with its -1 default, the exact incoming-call scan result (one direct site in one caller FDE), and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the caller, whether the gate guards a sentinel or a self-referential node, and any wider pair-load family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a pointer is loaded from a struct field, gated on a self-compare, and otherwise chased through two more loads to a deep field. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5172e50`, no open pull request title mentions it or two-hop-field-load, and its bytes overlap nothing in packets #1–#80.

## Scout note

The round-12 scout note listed this window (ranked #4, the last ranked item) with FDE `[0x5172e50, 0x5172e77)`, 39 bytes, 9 padding bytes, one direct caller boundary-confirmed, and no naming relocation. Every element verified exactly, including the full three-load chain, the self-compare gate, and the nearest claimed window (tiny two-byte gate `0x51647b0`, packet #72, `0xe6a0` away). No numeric correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the one direct site is an incoming call from one caller FDE — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_hop_field_load.py --check research/work-items/foundation-two-hop-field-load-94/evidence.json
python3 -m unittest tests.test_foundation_two_hop_field_load -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5172e50 --stop-address=0x5172e80 artifacts/node/94/hl-node
objdump -d --start-address=0x5152280 --stop-address=0x51524a9 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its nine padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE, from which the call site was confirmed as an instruction start. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c50c` (this window), `0x29c520` (the next FDE), `0x6344bc` (the caller FDE), plus the shared CIEs at offsets `0` and `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c50c` describes `[0x5172e50, 0x5172e77)`, 39 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Nine `int3` bytes follow: the next FDE starts exactly at `0x5172e80` (record at `.eh_frame+0x29c520`, range to `0x5172f91`). The unwind-index stride is therefore 48 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x1cb050`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: two-hop field load with -1 default, no calls, one forward branch

Input: `rdi` = struct pointer. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5172e50` | `endbr64` | Landing pad |
| `0x5172e54` | `mov 0x8(%rdi),%rax` | Load the pointer `p` |
| `0x5172e58` | `mov $0xffffffffffffffff,%rdx` | Stage the -1 default |
| `0x5172e5f` | `cmp (%rax),%rax` | Self-compare: `p` against `[p]` |
| `0x5172e62` | `je 0x5172e73` | Equal → return -1 |
| `0x5172e64` | `mov 0x8(%rax),%rax` | First hop: `q = [p+8]` |
| `0x5172e68` | `mov 0x10(%rax),%rax` | Second hop: `r = [q+0x10]` |
| `0x5172e6c` | `mov 0xcb8(%rax),%rdx` | Deep field: `rdx = [r+0xcb8]` |
| `0x5172e73` | `mov %rdx,%rax` | Result into `rax` |
| `0x5172e76` | `ret` | |

Rule: `p = [rdi+8]`; if `p == [p]`, return -1; else `q = [p+8]`, `r = [q+0x10]`, return `[r+0xcb8]`. The gate is a self-compare (pointer value vs pointed-to value), not a null check — nothing in the bytes tests `p` against zero, and the -1 path fires exactly when the pointed-to qword equals the pointer itself.

Worked edges: `p` self-referential (`[p] == p`) → -1; chain `[rdi+8]=0x3000`, `[0x3000]=0x9999`, `[0x3008]=0x4000`, `[0x4010]=0x5000`, `[0x5000+0xcb8]=42` → 42; same chain with the deep field 0 → 0.

### Distinction from packet #40's pair load

Packet #40 (`0x502b460`) loads two fields from the **same** base pointer (`base+0x198` and `base+0x190`), with no chaining — neither load's address depends on the other's result — and no gate at all. This window is a different shape: three **chained** dereferences, each address depending on the previous load's result, gated on a self-compare with a -1 default. The two windows share only the broad "several loads" appearance; no shared primitive is claimed, and no pair-load census is built here.

### Incoming calls: one direct site, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site whose rel32 lands on the window start:

| Site | Caller FDE | Setup immediately before the call |
| --- | --- | --- |
| `0x51523bc` (bytes `e8 8f 0a 02 00`) | `[0x5152280, 0x51524a9)` | `mov 0xcb8(%rax),%rbp`, preceded by `add $0x8f0,%rdi` |

The site was confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. Caller purpose is not claimed; the setups are locked as bytes only.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The window is labeled "two-hop field load" for convenience. The label is an inference from the observed operations, kept separate from the rule above.
- The -1 default is read as a sentinel-style return for the self-referential case; what it means to the caller is not claimed.
- The window is pair-load class in appearance only (see the #40 distinction above); nothing in the bytes shows it belongs to a wider family.

## Unknowns

- What the struct is, what the pointer field points to, and what the deep `+0xcb8` field means.
- Whether the self-compare guards a sentinel, a self-referential node, or something else entirely.
- What the caller does with the result, and whether any indirect caller or tail-jump entrant reaches this window beyond the one direct site found.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
