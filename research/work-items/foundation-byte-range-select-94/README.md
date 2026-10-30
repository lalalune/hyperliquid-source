# foundation-byte-range-select-94: what does the byte-range select window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 78-byte FDE window with two padding bytes, the byte-classified select/transform rule it implements, the exact incoming-call scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of either argument, the identity or purpose of any caller, and any wider select family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a two-argument select whose return is gated on the low byte of the first argument, with three distinct transform classes for out-of-range bytes. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x359be70`, no open pull request title mentions it or byte-range select, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, or vip-classifier packets.

## Scout-note correction (read first)

The round-5 scout note described this window as "if the low byte of edi lies in [0xc0, 0xe0) return esi, else return edi", with the 0x8f/0x90/0xa0 branches "unreachable for in-range bytes". The retained bytes contradict that summary in direction and in completeness, and this packet binds the corrected behavior:

- The direction is reversed: in-range bytes return **edi** unchanged (the `ret` at `0x359be80` falls through with `eax` still holding the first instruction's `mov %edi,%eax`), and out-of-range bytes return **esi**, transformed or not.
- The 0x8f/0x90/0xa0 branches are not dead code. They are reached only for out-of-range bytes, and for out-of-range bytes they are the body of the function: byte `<= 0x8f` (except 0) maps the low byte of esi through `(esi & 0x0f) | 0x80`; byte `0x90` maps it through `(esi & 0x0f) | 0x90`; byte `0xa0` maps it through `(esi & 0x1f) | 0xa0`. The scout's remark is true only in the narrow sense that these branches are never reached for in-range bytes, because the range check returns first.
- The scout note also gave the FDE end as `0x359bebd`. The FDE record ends at `0x359bebe`: the final `ret` sits at `0x359bebd` and is one byte long, so the window is 78 bytes, not 77.

Nothing in the scout note was trusted over the disassembly; every element below was verified from the bytes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_range_select.py --check research/work-items/foundation-byte-range-select-94/evidence.json
python3 -m unittest tests.test_foundation_byte_range_select -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x359be70 --stop-address=0x359bec0 artifacts/node/94/hl-node
objdump -d --start-address=0x31ed6b0 --stop-address=0x31ed886 artifacts/node/94/hl-node
objdump -d --start-address=0x31f0b40 --stop-address=0x31f0c88 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its two padding bytes. The `caller.objdump.txt` file retains complete disassembly of the two caller FDEs at `0x31ed6b0` and `0x31f0b40`, from which the first three call sites were confirmed as instruction starts; the remaining 110 scan sites are retained as a list in `evidence.json` and re-verified by the checker, not individually confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x151fd8` (this window) and `0x151fec` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x151fd8` describes `[0x359be70, 0x359bebe)`, 78 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x359bebd` is inside the FDE).
- Two `int3` bytes (`0xcc`) follow at `0x359bebe`–`0x359bebf`, and the next FDE starts exactly at `0x359bec0` (record at `.eh_frame+0x151fec`, range 159 bytes to `0x359bf5f`). The unwind-index stride is therefore 80 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: byte-classified select/transform, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x359be70` | `mov %edi,%eax` | Return register seeded with the first argument |
| `0x359be72` | `movzbl %al,%ecx` | `b = edi & 0xff`, zero-extended; upper bytes of edi ignored |
| `0x359be75` | `lea -0xc0(%rcx),%edx` | `b - 0xc0` (mod 2^32) |
| `0x359be7b` | `cmp $0x20,%edx` | Range width 0x20 |
| `0x359be7e` | `jae 0x359be81` | Out-of-range (unsigned `b - 0xc0 >= 0x20`) goes to the transform body |
| `0x359be80` | `ret` | In-range: return edi unchanged |
| `0x359be81` | `cmp $0x8f,%ecx` | Low-byte class boundary |
| `0x359be87` | `jle 0x359bea4` | `b <= 0x8f` (signed; `b` is 0..255, so no sign subtlety) |
| `0x359be89` | `cmp $0x90,%ecx` | |
| `0x359be8f` | `je 0x359beb3` | `b == 0x90` |
| `0x359be91` | `cmp $0xa0,%ecx` | |
| `0x359be97` | `jne 0x359bea1` | `b != 0xa0` returns esi unchanged |
| `0x359be99` | `and $0x1f,%sil` | `b == 0xa0`: keep low 5 bits of esi's low byte |
| `0x359be9d` | `or $0xa0,%sil` | `b == 0xa0`: set bits to `0xa0` |
| `0x359bea1` | `mov %esi,%eax` | Return esi (possibly transformed) |
| `0x359bea3` | `ret` | |
| `0x359bea4` | `test %ecx,%ecx` | `b <= 0x8f` path: is `b` zero? |
| `0x359bea6` | `je 0x359bea1` | `b == 0` returns esi unchanged |
| `0x359bea8` | `and $0xf,%sil` | `b` in [1, 0x8f]: keep low nibble of esi's low byte |
| `0x359beac` | `or $0x80,%sil` | `b` in [1, 0x8f]: set bits to `0x80` |
| `0x359beb0` | `mov %esi,%eax` | |
| `0x359beb2` | `ret` | |
| `0x359beb3` | `and $0xf,%sil` | `b == 0x90`: keep low nibble |
| `0x359beb7` | `or $0x90,%sil` | `b == 0x90`: set bits to `0x90` |
| `0x359bebb` | `mov %esi,%eax` | |
| `0x359bebd` | `ret` | |

The rule is therefore, with `b = edi & 0xff`:

- `0xc0 <= b < 0xe0`: return edi (full 32 bits, unchanged).
- `b == 0`: return esi unchanged.
- `1 <= b <= 0x8f`: return `(esi & 0xffffff00) | ((esi & 0x0f) | 0x80)`.
- `b == 0x90`: return `(esi & 0xffffff00) | ((esi & 0x0f) | 0x90)`.
- `b == 0xa0`: return `(esi & 0xffffff00) | ((esi & 0x1f) | 0xa0)`.
- Otherwise (`b` in [0x91, 0x9f] ∪ [0xa1, 0xbf] ∪ [0xe0, 0xff]): return esi unchanged.

Worked edges: `b = 0xc0` and `b = 0xdf` return edi; `b = 0x41` with esi low byte `0x78` returns `(esi & 0xffffff00) | 0x88`; `b = 0x90` with the same esi returns `... | 0x98`; `b = 0xa0` returns `... | 0xb8`. Transform cases modify only the low byte of esi; the upper 24 bits of esi pass through in every path, and in-range returns carry the full 32-bit edi. The window contains no call opcode; it has five conditional branches, all resolving inside the window.

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly 113 direct `e8` call sites targeting this window, retained as a list in `evidence.json` and re-verified by the checker. The scan is explicitly not a complete xref census, and only the first three sites (`0x31ed745`, `0x31ed78d` in caller FDE `0x31ed6b0..0x31ed886`; `0x31f0bc5` in caller FDE `0x31f0b40..0x31f0c88`) were confirmed as instruction starts by linear disassembly from their caller FDE starts, with objdump resolving each call target to `0x359be70`. The remaining 110 sites are scan results, not individually confirmed instruction starts.
- No relocation record of any type in `.rela.dyn` names this window as addend (a full `readelf -r` grep for `0x359be70` also finds zero hits). The window is reached by direct calls, not by a data pointer, as far as the retained evidence shows.

## Inferences

- The window is a byte-classified select over two arguments, returning the first argument for one byte range and the second argument — sometimes with its low byte remapped — otherwise. That shape is an inference from the instruction sequence, kept separate from the observed rule above.
- The "byte-range select" label is an inference, not a source-level name.

## Unknowns

- What either argument means, why the range [0xc0, 0xe0) is special, and what the three transform classes represent: unknown, and not claimed.
- The identity, purpose, and argument values of the 113 callers: unknown, and not claimed. The two retained caller FDE ranges anchor only the first three call sites.
- Whether any caller reaches this window by an indirect call or a data pointer: unknown; the byte-pattern scan is not a complete xref census.

## Limits

- No stdlib type, source-level function, argument meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The checker locks the full 113-site scan list, but only three sites were confirmed as instruction starts; a scan site could in principle be an `e8` byte inside another instruction.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
