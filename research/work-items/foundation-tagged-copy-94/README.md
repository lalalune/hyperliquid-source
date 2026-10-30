# foundation-tagged-copy-94: what does the tagged 40-byte copy window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 32-byte FDE window with zero padding, the 40-byte output shape it writes, the exact no-caller scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of the tag value, the meaning of the copied bytes, and the identity of any caller or consumer; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two unaligned 16-byte loads, two unaligned 16-byte stores, and one 8-byte tag store, with no calls and no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x22155a0`, no open pull request title mentions it or tagged-copy, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, chunk-equality, or error-name packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tagged_copy.py --check research/work-items/foundation-tagged-copy-94/evidence.json
python3 -m unittest tests.test_foundation_tagged_copy -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x22155a0 --stop-address=0x22155c0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window (there is no padding to retain: the next FDE starts exactly at the FDE end). The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x573cc` (this window) and `0x573e0` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and zero padding

- `.eh_frame+0x573cc` describes `[0x22155a0, 0x22155c0)`, 32 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x22155bf` is inside the FDE).
- There is **no padding** after this window: the next FDE starts exactly at `0x22155c0` (record at `.eh_frame+0x573e0`, range 665 bytes to `0x2215859`). The unwind-index stride therefore equals the FDE extent, 32 bytes; any description of this window as padded would be wrong, and the checker locks the next FDE's PC as equal to the FDE end.
- The bytes immediately before the window are the tail of a different, larger function: a `jmp` at `0x2215598` followed by three `int3` bytes (`0xcc`) at `0x221559d`–`0x221559f`. Those int3 bytes pad the previous function, not this window, and are not part of this packet's claim.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: two 16-byte copies and one tag store, no calls, no branches

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x22155a0` | `mov %rdi,%rax` | Out pointer returned in rax |
| `0x22155a3` | `movups (%rsi),%xmm0` | Load input bytes 0..15 |
| `0x22155a6` | `movups 0x10(%rsi),%xmm1` | Load input bytes 16..31 |
| `0x22155aa` | `movups %xmm1,0x18(%rdi)` | Store input bytes 16..31 at out+0x18 |
| `0x22155ae` | `movups %xmm0,0x8(%rdi)` | Store input bytes 0..15 at out+0x8 |
| `0x22155b2` | `movabs $0x8000000000000014,%rcx` | Tag constant |
| `0x22155bc` | `mov %rcx,(%rdi)` | Store tag at out+0 |
| `0x22155bf` | `ret` | Return out pointer |

The output shape, with all arithmetic over plain bytes, is:

- `out[0..8] = 0x8000000000000014` (little-endian: `14 00 00 00 00 00 00 80`)
- `out[8..24] = in[0..16]`
- `out[24..40] = in[16..32]`
- return value `rax = out` (the input `rdi`, unchanged)

Note the store order: the second 16-byte chunk is stored before the first, but the final memory state is the same as a straight copy — out+8 holds the first 16 input bytes and out+0x18 holds the second 16. The tag store happens last, so no store in this window overwrites another.

### Incoming edges: no direct callers, no naming relocation

- The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to this window. This is explicitly not a complete xref census: register-indirect references, other pointer paths, prefixes, and data sections are not covered.
- No relocation record in `.rela.dyn` of any type names this window as addend (verified over the full section, not just RELATIVE records). The window is therefore not referenced by any load-time data pointer either, as far as the relocation table shows. Whether any caller reaches it through a computed address is not closed here.

## Inferences and unknowns

- **Inferred:** this is a tagged 40-byte copy: its 8-byte tag prefix, 32 copied bytes, and out-pointer return support that label. The binary has no recovered symbol name here. Neither the source-level function name, the meaning of the tag value `0x8000000000000014`, nor the meaning of the copied bytes is proven.
- The input and output are 32-byte and 40-byte regions respectively; whether they are one struct, two fields, or a tagged value plus payload is not decided by these bytes.
- The absence of direct callers and naming relocations is real for the scans run, but the window's actual callers, if any, are not identified. The byte-pattern scan is not a complete xref census.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed FDE extent, next-FDE PC, or relative relocation target;
- changed instruction bytes at any fixed offset, including the tag constant;
- changed copy-rule edges (all-zero, sequential, and all-0xff inputs);
- any direct caller or naming relocation appearing in the scans.

## Limits

- No source-level function name, tag meaning, or copied-byte meaning is claimed anywhere.
- The callers of this window are not identified, and the scans run are not a complete xref census.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
