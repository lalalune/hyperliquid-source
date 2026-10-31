# foundation-double-gate-94: what does the double threshold gate window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 27-byte FDE window, its five int3 padding bytes, the .rodata constant it compares against, the one RELATIVE slot that names it, and the exact low-byte threshold rule.
- Excluded: the compared value's meaning, the constant's meaning beyond its file bytes, the callers' behavior (there are no direct callers), the next FDE, other threshold helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one field-pointer load, one double load, one comisd against a .rodata constant, one setae, no calls, no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5028a40`, no open pull request title mentions it or double-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, or tail-gate packets.

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_double_gate.py --check research/work-items/foundation-double-gate-94/evidence.json
python3 -m unittest tests.test_foundation_double_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5028a40 --stop-address=0x5028a60 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. Note: GNU objdump wraps the comisd instruction's byte column, so the final displacement byte `fb` appears on its own line (`5028a56: fb`); the raw 27-byte body locked by the checker is authoritative, and the comisd is one 8-byte instruction at `0x5028a4f`. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x291380`, and the next FDE at `0x291394`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x291380` describes `[0x5028a40, 0x5028a5b)`, 27 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5028a5a` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x5028a60`, only because five `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those five padding bytes, and the checker locks the 27-byte body and the padding separately. The next FDE starts exactly at `0x5028a60` (range 23 bytes to `0x5028a77`).
- No direct `e8` call to this window appears in the exact `.text` byte-pattern scan covering 70,370,352 bytes. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Instruction sequence

Offsets are relative to the FDE start `0x5028a40`:

| Offset | Bytes | Instruction |
| ------ | ----- | ----------- |
| 0x00 | `f3 0f 1e fa` | `endbr64` |
| 0x04 | `48 8b 86 38 0f 00 00` | `mov 0xf38(%rsi),%rax` — field pointer load |
| 0x0b | `f2 0f 10 00` | `movsd (%rax),%xmm0` — double load through the pointer |
| 0x0f | `66 0f 2f 05 d9 1c 1e fb` | `comisd 0x20a730(%rip),%xmm0` — compare against the .rodata constant |
| 0x17 | `0f 93 c0` | `setae %al` — 1 iff the double is above or equal, unordered (NaN) excluded |
| 0x1a | `c3` | `ret` |

### The compared constant

- The comisd displacement resolves to `0x20a730` in `.rodata`. The eight file bytes there are `00 00 00 00 00 00 f0 3f`, which decode as the IEEE 754 double **1.0** exactly. No other meaning is claimed for the constant.

### The low-byte-only return

- No instruction in the window zeroes `eax` before the `setae`. The `setae` writes only `al`; the upper bytes of `rax` retain whatever the caller left there. The gate bit is therefore the **low byte only**: `(rax & 0xff) == 1` iff the compared double is >= 1.0, else 0. The checker locks this low-byte rule and never claims a full-width 0/1 return. This is the same precision caveat as packet #27's range-membership test.

### NaN behavior

- `comisd` sets CF=1 on an unordered comparison, so `setae` is false for NaN. The rule therefore yields 0 for NaN, for any negative value, and for zero, and 1 for 1.0, values above 1.0, and positive infinity. Negative infinity yields 0.

### Data edge

- Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x5759108` in `.data.rel.ro`. The file holds 0 at that slot; the value is applied only at load time. This is a data-pointer reference, not a direct call, and no provenance beyond that one slot is claimed.

## Inferences

- The "double threshold gate" label is an inference from the observed instruction shape (double load, comisd against 1.0, setae). It is kept separate from the observed rule above.
- Nothing else is inferred: no source-level function, no value meaning, no constant meaning, no caller purpose, and no component ownership are claimed.

## Unknowns

- What the compared double represents, why the threshold is exactly 1.0, who holds the data pointer at slot `0x5759108`, and whether any caller reaches this window through a register-indirect or data path the byte-pattern scan cannot see.
- The next FDE at `0x5028a60` (23 bytes) is a different window and is not analyzed here.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of direct callers does not prove the window is unreachable.
- The absence of a zeroing instruction means the full-width return value is not determined by this window; only the low byte is claimed.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
