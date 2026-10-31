# foundation-index-clamp-stride-94: what does the index-clamp plus 80-byte-stride pointer computation window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 114-byte FDE window with fourteen padding bytes, the index-clamp plus 80-byte-stride rule it implements, the exact incoming-call scan result (four direct sites), and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the callers, and any wider clamp/stride family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: four qwords read from a struct, three indices computed with an unsigned clamping branch, and four pointers stored — each index scaled by 80 and added to the struct's base pointer, with the bare base itself in the third slot. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window is heavier than the recent single-gate packets (four outputs, a clamping branch, four callers), and that weight is stated head-on rather than buried: it is bound because the rule locks exactly from its own bytes — every instruction at a fixed offset, every branch target on a retained instruction start, all four call sites boundary-confirmed — not because it is small. No caller context is needed to state the rule, and none is claimed.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x2517660`, no open pull request title mentions it or index-clamp-stride, and its bytes overlap nothing in packets #1–#74.

## Scout note

The round-11 scout note listed this window (backup B3) with FDE `[0x2517660, 0x25176d2)`, 114 bytes, 14 padding bytes, four direct callers all boundary-confirmed, and no naming relocation. Every element verified exactly, and no correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the four direct sites are incoming calls from four caller FDEs — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_index_clamp_stride.py --check research/work-items/foundation-index-clamp-stride-94/evidence.json
python3 -m unittest tests.test_foundation_index_clamp_stride -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x2517660 --stop-address=0x25176e0 artifacts/node/94/hl-node
objdump -d --start-address=0x22807d0 --stop-address=0x228177d artifacts/node/94/hl-node
objdump -d --start-address=0x2281780 --stop-address=0x2282801 artifacts/node/94/hl-node
objdump -d --start-address=0x2285500 --stop-address=0x2285fb3 artifacts/node/94/hl-node
objdump -d --start-address=0x2285fc0 --stop-address=0x2286a73 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its fourteen padding bytes. The `caller.objdump.txt` file retains complete disassembly of all four caller FDEs, from which the four call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x85a60` (this window), `0x85a74` (the next record in `.eh_frame` order), `0x3e68d0` (the address-order next FDE), and `0x5a058`, `0x5a0a8`, `0x3ba018`, `0x3ba06c` (the four caller FDEs), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x85a60` describes `[0x2517660, 0x25176d2)`, 114 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x25176d1` is inside the FDE).
- Fourteen `int3` bytes (`0xcc`) follow at `0x25176d2`–`0x25176df`, and the address-order next FDE starts exactly at `0x25176e0` (record at `.eh_frame+0x3e68d0`, range to `0x2517905`). The unwind-index stride is therefore 128 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately. The next record in `.eh_frame` order (offset `0x85a74`, PC `0x2517ba0..0x2517c05`) is a different function and is locked only as the section-order neighbor, not as the address-order successor.
- The window opens directly with the output-pointer move — no `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: index clamp plus 80-byte-stride pointers, no calls, three forward branches

Inputs: `rdi` = output pointer (four qword slots), `rsi` = struct pointer. Fields read: `A = [rsi+0x0]`, `base = [rsi+0x8]`, `B = [rsi+0x10]`, `N = [rsi+0x18]`. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x2517660` | `mov %rdi,%rax` | Output pointer saved |
| `0x2517663` | `mov 0x18(%rsi),%r8` | `N` loaded |
| `0x2517667` | `test %r8,%r8` | Zero-count test |
| `0x251766a` | `je 0x2517697` | Zero count → all indices zero |
| `0x251766c` | `mov (%rsi),%rdx` | `A` loaded |
| `0x251766f` | `mov 0x10(%rsi),%rcx` | `B` loaded |
| `0x2517673` | `xor %edi,%edi` | Low select cleared |
| `0x2517675` | `cmp %rdx,%rcx` | Compare `B` against `A` |
| `0x2517678` | `cmovae %rdx,%rdi` | `lo = A` if `B >= A` unsigned, else `0` |
| `0x251767c` | `sub %rdi,%rcx` | `i0 = B - lo` |
| `0x251767f` | `mov %rdx,%r9` | Remainder starts at `A` |
| `0x2517682` | `sub %rcx,%r9` | `r9 = A - i0` |
| `0x2517685` | `mov %r8,%rdi` | Third index starts at `N` |
| `0x2517688` | `sub %r9,%rdi` | `i2 = N - r9` |
| `0x251768b` | `ja 0x251769d` | Above → keep `(i0, A, i2)` |
| `0x251768d` | `add %rcx,%r8` | `N + i0` |
| `0x2517690` | `xor %edi,%edi` | Third index cleared |
| `0x2517692` | `mov %r8,%rdx` | `i1 = N + i0` |
| `0x2517695` | `jmp 0x251769d` | To the store phase |
| `0x2517697` | `xor %ecx,%ecx` | Zero-count: `i0 = 0` |
| `0x2517699` | `xor %edx,%edx` | Zero-count: `i1 = 0` |
| `0x251769b` | `xor %edi,%edi` | Zero-count: `i2 = 0` |
| `0x251769d` | `mov 0x8(%rsi),%rsi` | `base` loaded |
| `0x25176a1` | `lea (%rcx,%rcx,4),%rcx` | `i0 * 5` |
| `0x25176a5` | `shl $0x4,%rcx` | `i0 * 80` |
| `0x25176a9` | `add %rsi,%rcx` | `base + i0*80` |
| `0x25176ac` | `lea (%rdx,%rdx,4),%rdx` | `i1 * 5` |
| `0x25176b0` | `shl $0x4,%rdx` | `i1 * 80` |
| `0x25176b4` | `add %rsi,%rdx` | `base + i1*80` |
| `0x25176b7` | `lea (%rdi,%rdi,4),%rdi` | `i2 * 5` |
| `0x25176bb` | `shl $0x4,%rdi` | `i2 * 80` |
| `0x25176bf` | `add %rsi,%rdi` | `base + i2*80` |
| `0x25176c2` | `mov %rcx,(%rax)` | Store slot 0 |
| `0x25176c5` | `mov %rdx,0x8(%rax)` | Store slot 1 |
| `0x25176c9` | `mov %rsi,0x10(%rax)` | Store slot 2 = bare base |
| `0x25176cd` | `mov %rdi,0x18(%rax)` | Store slot 3 |
| `0x25176d1` | `ret` | Returns, no value claimed |

The rule is therefore, with all arithmetic wrapping at 64 bits: if `N == 0`, indices are `(0, 0, 0)`; else `lo = A` if `B >= A` unsigned else `0`, `i0 = B - lo`, `r9 = A - i0`, `i2 = N - r9`, and the indices are `(i0, A, i2)` when `i2 > r9` unsigned, else `(i0, N + i0, 0)`. The stored outputs are `base + i0*80`, `base + i1*80`, `base`, `base + i2*80`. The third slot is always the bare base — it is not a scaled index.

Worked edges (all verified against the branch structure, including wraparound):

- `A=10, B=25, N=100` → `lo=10, i0=15, r9` wraps to `2^64-5`, `i2=105`, not above → `(15, 115, 0)`.
- `A=10, B=5, N=100` → `lo=0, i0=5, r9=5, i2=95`, above → `(5, 10, 95)`.
- `A=10, B=5, N=3` → `lo=0, i0=5, r9=5, i2` wraps to `2^64-2`, above → `(5, 10, 2^64-2)`. The wrap is stated, not smoothed over: when `N < A - B` with `B < A`, the third index is a wrapped huge value, and the `ja` is taken because that wrapped value exceeds `r9`.
- `A=10, B=25, N=5` → `lo=10, i0=15, r9` wraps, `i2=10`, not above → `(15, 20, 0)`.
- `A=10, B=5, N=10` → `i2 == r9 == 5`; the `ja` requires strictly above, so equality falls through → `(5, 15, 0)`. The boundary is exact, not approximate.
- `A=10, B=10, N=7` → `lo=10, i0=0, r9=10, i2` wraps to `2^64-3`, above → `(0, 10, 2^64-3)`.
- `A=0, B=0, N=5` → `(0, 0, 5)`.
- `N=0` (any `A`, `B`) → `(0, 0, 0)`; all four outputs equal `base`.

The window contains no call opcode and exactly three forward branches (`je`, `ja`, `jmp`), all landing on retained instruction starts. The `cmovae`/`ja` pair is unsigned throughout; no signed interpretation is claimed.

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly four direct `e8` call sites: `0x228149e` (bytes `e8 bd 61 29 00`), `0x2282484` (bytes `e8 d7 51 29 00`), `0x2285c23` (bytes `e8 38 1a 29 00`), `0x22866e3` (bytes `e8 78 0f 29 00`). Each was confirmed as an instruction start by linear disassembly from its caller FDE start, and objdump resolves each call target to `0x2517660`. The scan is explicitly not a complete xref census.
- Caller setups, locked in the checker: sites 1–2 load the output pointer from a callee-saved register (`r12`/`r15`) and the struct pointer from a stack slot (`0x68(%rsp)`/`0x70(%rsp)`); sites 3–4 compute both arguments with `lea` (`0x20(%rbx)` for the struct, `0x40(%rsp)` for the output). Caller purpose is not claimed; the two setup shapes are recorded, not merged into one claim.
- No relocation record of any type in any `.rela.*` section names this window as addend (a full `readelf -r` scan of 80,300 entries: 80,022 `.rela.dyn` + 278 `.rela.plt`, finds zero hits). The window is reached by direct calls, not by a data pointer, as far as the retained evidence shows.
- Nearest claimed window: tail-gate `0x250ab00` (packet #31), `0xcb60` away.

## Inferences

- The window computes three scaled pointers plus a bare base pointer from one struct, with an unsigned clamping branch selecting the second and third indices. That shape is an inference from the instruction sequence, kept separate from the observed rule above.
- The "index-clamp plus 80-byte-stride" label is an inference, not a source-level name. The stride 80 is observed (lea `*5` then shift `*16` for each index); what 80-byte elements are is not claimed.
- The wrap edge (`N < A - B` with `B < A`) is recorded as observed unsigned arithmetic, not as a claimed intended behavior.

## Unknowns

- What the struct fields mean, what the 80-byte stride steps over, and what the four output pointers are used for: unknown, and not claimed.
- The identity, purpose, and argument values of the four callers: unknown, and not claimed. The caller FDE ranges are retained only to anchor the call sites.
- Whether any caller reaches this window by an indirect call or a data pointer: unknown; the byte-pattern scan is not a complete xref census.
- Whether the wrapped third index is ever exercised by a real caller: unknown; the edge is a property of the bytes, not a claimed execution trace.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
