# foundation-half-swap-94: what does the 32-byte lane-reversal window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 80-byte FDE window with zero padding, the 32-byte output shape it writes, the exact no-caller scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of the input and output bytes, and the identity of any caller or consumer; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: four 8-byte loads, four byte-swaps, and eight 4-byte stores, with no calls and no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x56544a0` except one line in the RE-001 gap inventory listing the 7-byte gap `0x5654499–0x56544a0` that *ends* where this window starts (not a claim on the window itself), no open pull request title mentions it or half-swap, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, vip-classifier, or byte-range-select packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_half_swap.py --check research/work-items/foundation-half-swap-94/evidence.json
python3 -m unittest tests.test_foundation_half_swap -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x56544a0 --stop-address=0x56544f0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window (there is no padding to retain: the next FDE starts exactly at the FDE end). The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2daf80` (this window) and `0x2daf94` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and zero padding

- `.eh_frame+0x2daf80` describes `[0x56544a0, 0x56544f0)`, 80 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `repz ret` at `0x56544ee` is inside the FDE).
- There is **no padding** after this window: the next FDE starts exactly at `0x56544f0` (record at `.eh_frame+0x2daf94`, range 25 bytes to `0x5654509`). The unwind-index stride therefore equals the FDE extent, 80 bytes; any description of this window as padded would be wrong, and the checker locks the next FDE's PC as equal to the FDE end. The next window is a different function (a byte-copy loop subtracting `rsi` from `rdi`), not bound here and never as a pair with this window.
- The bytes immediately before the window are the tail of a different, larger function: a `repz ret` at `0x5654497` followed by a 7-byte gap (`nop` at `0x5654499`, `nopw` at `0x565449a`–`0x565449f`) — the same gap the RE-001 inventory lists as `0x5654499–0x56544a0`. Those bytes pad the previous function, not this window, and are not part of this packet's claim.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Scout correction: not a half-swap, a per-lane byte reversal

The round-6 scout note described this window as a 32-bit-half swap: out word = in word rotated by 32 bits, `out+0..3 = in[4..8]`, `out+4..8 = in[0..4]`. The retained bytes show that is wrong, and the correction is stated here prominently because the PR title and body must use the corrected behavior.

The store sequence is: `mov %r8d,0x4(%rdi)` stores the **low** 32 bits of the bswapped word, then `shr $0x20,%r8` and `mov %r8d,(%rdi)` stores the **high** 32 bits. The low 32 bits of `bswap(w)` are the byte-reversed second half of `w`, and the high 32 bits are the byte-reversed first half — not the halves in their original order. Concretely, for input bytes `01 02 03 04 05 06 07 08`, the scout's rule predicts `05 06 07 08 01 02 03 04`, while the retained bytes produce `04 03 02 01 08 07 06 05`. Two independent derivations (a lane-reversal restatement and an instruction-semantics emulation of bswap-plus-stores) agree on all inputs, including the sequential edge below.

### Body behavior: four loads, four bswaps, eight stores, no calls, no branches

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x56544a0` | `endbr64` | Entry |
| `0x56544a4` | `mov (%rsi),%r8` | Load input word 0 |
| `0x56544a7` | `mov 0x8(%rsi),%r9` | Load input word 1 |
| `0x56544ab` | `mov 0x10(%rsi),%r10` | Load input word 2 |
| `0x56544af` | `bswap %r8` | Reverse word 0 |
| `0x56544b2` | `mov 0x18(%rsi),%r11` | Load input word 3 |
| `0x56544b6` | `bswap %r9` | Reverse word 1 |
| `0x56544b9` | `mov %r8d,0x4(%rdi)` | Store byte-reversed second half of word 0 at out+4 |
| `0x56544bd` | `bswap %r10` | Reverse word 2 |
| `0x56544c0` | `mov %r9d,0xc(%rdi)` | Store byte-reversed second half of word 1 at out+12 |
| `0x56544c4` | `bswap %r11` | Reverse word 3 |
| `0x56544c7` | `mov %r10d,0x14(%rdi)` | Store byte-reversed second half of word 2 at out+20 |
| `0x56544cb` | `shr $0x20,%r8` | Shift word 0 to its high half |
| `0x56544cf` | `mov %r11d,0x1c(%rdi)` | Store byte-reversed second half of word 3 at out+28 |
| `0x56544d3` | `shr $0x20,%r9` | Shift word 1 to its high half |
| `0x56544d7` | `mov %r8d,(%rdi)` | Store byte-reversed first half of word 0 at out+0 |
| `0x56544da` | `shr $0x20,%r10` | Shift word 2 to its high half |
| `0x56544de` | `mov %r9d,0x8(%rdi)` | Store byte-reversed first half of word 1 at out+8 |
| `0x56544e2` | `shr $0x20,%r11` | Shift word 3 to its high half |
| `0x56544e6` | `mov %r10d,0x10(%rdi)` | Store byte-reversed first half of word 2 at out+16 |
| `0x56544ea` | `mov %r11d,0x18(%rdi)` | Store byte-reversed first half of word 3 at out+24 |
| `0x56544ee` | `repz ret` | Return, no value set |

The output shape, with all arithmetic over plain bytes, is:

- For each 8-byte word `w` in 0..3: `out[w*8..w*8+4] = reverse(in[w*8..w*8+4])` and `out[w*8+4..w*8+8] = reverse(in[w*8+4..w*8+8])`.
- Equivalently: each of the eight 32-bit lanes is byte-reversed in place; lanes do not move.
- `rax` is never written, so this window determines no return value; `r8`–`r11` are caller-saved scratch.
- Note the store order: each bswapped word's low half is stored before its high half, but the final memory state is the per-lane reversal above — no store in this window overwrites another.

### Incoming edges: no direct callers, no naming relocation

- The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to this window. This is explicitly not a complete xref census: register-indirect references, other pointer paths, prefixes, and data sections are not covered.
- No relocation record in `.rela.dyn` of any type names this window as addend (verified over the full section, not just RELATIVE records). The window is therefore not referenced by any load-time data pointer either, as far as the relocation table shows. Whether any caller reaches it through a computed address is not closed here.

## Inferences and unknowns

- **Inferred:** this is a 32-byte lane-reversal helper: four loads, four bswaps, and eight stores with no calls or branches support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the meaning of the input and output bytes is proven.
- The input and output are both 32-byte regions; whether they are one struct, four words, or eight lanes is not decided by these bytes — the lane description is a statement about the byte rule, not about a type.
- The absence of direct callers and naming relocations is real for the scans run, but the window's actual callers, if any, are not identified. The byte-pattern scan is not a complete xref census.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed FDE extent, next-FDE PC, or relative relocation target;
- changed instruction bytes at any fixed offset, including the bswap/shift/store pattern;
- changed lane-reversal edges (all-zero, sequential, and all-0xff inputs);
- any direct caller or naming relocation appearing in the scans.

## Limits

- No source-level function name, input/output meaning, or caller purpose is claimed anywhere.
- The callers of this window are not identified, and the scans run are not a complete xref census.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
