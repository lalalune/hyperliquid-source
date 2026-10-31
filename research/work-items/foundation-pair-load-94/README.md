# foundation-pair-load-94: what does the pair-load window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 23-byte FDE window, its 9 int3 padding bytes, the exactly one naming relocation, the zero direct call sites, and the exact pair-load rule.
- Excluded: the fields' meaning, the base pointer's provenance, any caller behavior, the next FDE, other pair-load helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one base-pointer load, two field loads from the same base, no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x502b460`, no open pull request title mentions it or pair-load, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, or field-walk-shift packets.

This window is bound **alone**. No census of similar windows is claimed.

## Two scout corrections (read first)

The round-7 scout note for this window does **not** verify as written, in two places. The checker locks the verified bytes below, not the scout summary.

1. **Load order and chaining.** The scout shorthand read "rax = *(rax+0x190), rdx = *(rax+0x198) where base is *(rdi+0x28)", which implies the loads chain — the second load addressing from the first load's result. The retained bytes show the opposite order and no chaining: the `rdx` load from `base+0x198` comes **first** (bytes 8–14), and only then does the `rax` load from `base+0x190` (bytes 15–21) overwrite `rax`. Both loads address from the same base `*(rdi+0x28)`; neither load's address depends on the other's result. Swapping the two load instructions would leave the final register state unchanged.
2. **Naming relocation.** The scout note said no naming relocation exists. The retained bytes show **exactly one**: an `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x5759190` in `.data.rel.ro`, with file value 0 (applied only at load time). It is a data-pointer reference, not a direct call, and it does not identify the window's provenance.

Every other scouted element verified exactly: the FDE range, the 23-byte body, all five instructions, and zero direct callers.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_pair_load.py --check research/work-items/foundation-pair-load-94/evidence.json
python3 -m unittest tests.test_foundation_pair_load -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x502b460 --stop-address=0x502b480 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. There is intentionally no `caller.objdump.txt`: the window has zero direct callers, consistent with packets #32, #36, and #39. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x291484`, and the next FDE at `0x291498`. The checker locks the window FDE records and their CIE raw bytes, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value).
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x291484` describes `[0x502b460, 0x502b477)`, 23 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x502b476` is inside the FDE).
- Padding is **9 int3 bytes** (`cc` × 9) from `0x502b477` to the 32-byte stride end `0x502b480`, where the next FDE starts (range 15 bytes to `0x502b48f`). The checker locks the body and the padding separately; stride is not the FDE extent.

### Instruction walk

All offsets are relative to the FDE start `0x502b460`:

1. `endbr64` (bytes 0–3).
2. `mov 0x28(%rdi),%rax` (bytes 4–7): `base = *(rdi + 0x28)`.
3. `mov 0x198(%rax),%rdx` (bytes 8–14): `rdx = *(base + 0x198)`.
4. `mov 0x190(%rax),%rax` (bytes 15–21): `rax = *(base + 0x190)`. This overwrites `rax`, but the address it reads from is still `base` — the value loaded in step 3 plays no part in it.
5. `ret` (byte 22).

### Rule

```
base = *(rdi + 0x28)
at ret: rax = *(base + 0x190), rdx = *(base + 0x198)
```

No store, no call, no branch, no flag-dependent step. No return meaning beyond the two registers' contents is claimed: whether a caller reads this as a pair return is an inference about the caller, not an observation about this window.

### Data edge

Exactly one relocation record in any `.rela.*` section names this window as addend: `R_X86_64_RELATIVE` (type 8) in `.rela.dyn`, at slot `0x5759190` in `.data.rel.ro`, file value 0 (applied only at load time). The immediately adjacent slots in `.rela.dyn` name other nearby windows (`0x502b490`, `0x502b4f0`, `0x502b480`, `0x502bae0`); that adjacency is observed, and no shared table structure is claimed from it.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` call sites targeting this window. That scan is explicitly not a complete xref census: indirect calls, tail jumps, and data-pointer references (like the naming relocation above) are outside it.

## Inferences (kept separate from observations)

- The label "pair load" is an inference from the two-field load shape, not an observed name.
- The two loaded fields' types and meaning are unknown.
- The base pointer's provenance (what `rdi` points to) is unknown.
- Nothing about callers, component ownership, or source-level identity is claimed.

## Unknowns

- Whether any caller reads `rdx`, `rax`, or both.
- Whether the naming relocation's slot is ever read as a code pointer at runtime.
- The meaning of the `0x28`, `0x190`, and `0x198` offsets.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
