# foundation-chunk-equality-94: what does the 16-byte chunk-equality window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 33-byte FDE window, its fifteen int3 padding bytes, the 16-byte .rodata comparand, the one relocation slot naming the window, and the exact no-caller scan result.
- Excluded: the meaning of the chunk, of the constant, and of the returned rdi+0x38 pointer; the eleven same-shape sibling windows beyond their shape and comparands; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one 16-byte chunk is compared against one 16-byte constant, and the window returns rdi+0x38 on a full match, else 0. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x14b52b0`, no open pull request title mentions it or chunk-equality, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, or tzcnt-gate packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_chunk_equality.py --check research/work-items/foundation-chunk-equality-94/evidence.json
python3 -m unittest tests.test_foundation_chunk_equality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14b52b0 --stop-address=0x14b52e0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0xde88` (this window) and `0xde9c` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0xde88` describes `[0x14b52b0, 0x14b52d1)`, 33 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x14b52d0` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x14b52e0`, only because fifteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those fifteen padding bytes, and the checker locks the 33-byte body and the padding separately.
- The next FDE starts exactly at `0x14b52e0` (record at `.eh_frame+0xde9c`, range 33 bytes). It is a same-shape sibling window, not analyzed as part of this packet beyond the sibling note below.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: one chunk, one constant, two return values, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14b52b0` | `movdqu (%rsi),%xmm0` | Load 16 bytes at (rsi) |
| `0x14b52b4` | `pcmpeqb -0x12acfbc(%rip),%xmm0` | Compare against constant at `0x208300` |
| `0x14b52bc` | `pmovmskb %xmm0,%ecx` | Equality mask: bit per byte |
| `0x14b52c0` | `lea 0x38(%rdi),%rdx` | Match return value |
| `0x14b52c4` | `xor %eax,%eax` | Mismatch return value |
| `0x14b52c6` | `cmp $0xffff,%ecx` | Full-match test |
| `0x14b52cc` | `cmove %rdx,%rax` | Select match value on equality |
| `0x14b52d0` | `ret` | Return |

The rule, with all arithmetic over the retained bytes, is:

- `chunk = bytes at (rsi), 16 bytes`
- `if chunk == constant at 0x208300: return rdi+0x38; else: return 0`

The constant at `0x208300` (section `.rodata`, file offset = VA) is:

```
f86e515c5a0d0918c20ac95e03583e31
```

It is opaque bytes: no ASCII reading, no source-level name, and no meaning of the chunk, the constant, or the rdi+0x38 pointer is claimed.

### Data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` callers — explicitly not a complete xref census.
- One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x566e618` in `.data.rel.ro` (file stores 0, applied only at load time): the window is referenced by a data pointer, not by a direct call.

### Same-shape siblings, bound alone

Eleven same-shape windows follow at stride `0x30`, from `0x14b52e0` through `0x14b54c0`, each starting with the same `movdqu`/`pcmpeqb`/`pmovmskb`/`lea`/`xor`/`cmp`/`cmove`/`ret` shape and each comparing against a different 16-byte constant:

| Window | Comparand VA | Comparand bytes |
| --- | --- | --- |
| `0x14b52e0` | `0x2072e0` | `e73d5da0de0730902196b280937e3b5b` |
| `0x14b5310` | `0x205780` | `18978bb257d5dc38a39d9626eef330cd` |
| `0x14b5340` | `0x205790` | `9302580864d761d51371d3c634606ffb` |
| `0x14b5370` | `0x2054b0` | `b76d6b683e7e14f2af3e8f0bd8ebb83a` |
| `0x14b53a0` | `0x208650` | `e4fb4a93c0ee9c44ea0b5a5f63e0800e` |
| `0x14b53d0` | `0x203b20` | `2876156f612a7361ccade60e375e726e` |
| `0x14b5400` | `0x2072f0` | `4b77fd3bb270b80a74bae40bda048937` |
| `0x14b5430` | `0x203110` | `6d5dcbd62c50eb637841a657711b8bb9` |
| `0x14b5460` | `0x206820` | `507e85b2bc09f7468f129a7c0cbd7c63` |
| `0x14b5490` | `0x203810` | `d16caa81efab68379d4c146fcca68d2b` |
| `0x14b54c0` | `0x203820` | `e50b9db6f49bdddfff66a665d539d4bf` |

Only `0x14b52b0` is bound here; the siblings are explicitly not bound, never as a family.

### Scout-note correction

The scout note described "twelve same-shape siblings". The retained bytes show eleven: the stride-`0x30` run ends at `0x14b54c0`, and `0x14b54f0` starts a different function (`push %r15`). The README and this claim use eleven.

## Inferences and unknowns

- **Inferred:** this is a 16-byte chunk equality test: its unaligned load, byte-wise compare, full-mask test, and two-valued return support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the meaning of the chunk, the constant, or the rdi+0x38 pointer is proven.
- The single data-pointer reference's provenance beyond the one RELATIVE slot is not established, and the byte-pattern scan is not a complete xref census.
- The siblings' comparands are listed only to show they differ; no claim is made about what any sibling matches or why the family exists.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE records, or padding bytes;
- changed comparand target or constant bytes;
- changed relocation slots or slot file values;
- a changed incoming-call scan result;
- wrong equality-rule edges.

## Limits

- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
