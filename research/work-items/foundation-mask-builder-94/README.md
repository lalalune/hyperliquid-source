# foundation-mask-builder-94: what does the bitmask-builder window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 39-byte FDE window, its nine int3 padding bytes, one incoming direct call with its caller FDE, and the exact mask-builder rule including the shift-count masking caveat.
- Excluded: the global's runtime meaning, the caller's behavior beyond its call site and argument setup, the next FDE, other mask helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one full-width compare, one conditional jump, one shift, one subtract, one global store, no calls. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5521d10`, no open pull request title mentions it or mask-builder, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, or half-swap packets.

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_mask_builder.py --check research/work-items/foundation-mask-builder-94/evidence.json
python3 -m unittest tests.test_foundation_mask_builder -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5521d10 --stop-address=0x5521d40 artifacts/node/94/hl-node
objdump -d --start-address=0x54b9b60 --stop-address=0x54b9c44 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly of the caller FDE from its start through the call site (`0x54b9b60`..`0x54b9c44`); the full caller FDE is `[0x54b9b60, 0x54b9f1d)`, and only the retained region is claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2c927c`, the next FDE at `0x2c9294`, and the caller FDE at `0x2bfa24`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c927c` describes `[0x5521d10, 0x5521d37)`, 39 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5521d36` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x5521d40`, only because nine `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those nine padding bytes, and the checker locks the 39-byte body and the padding separately. The next FDE starts exactly at `0x5521d40`.
- No relocation of any type in `.rela.dyn` maps a slot to `0x5521d10`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller's argument setup is retained: `lea 0x2ce4dc(%rip),%r8` loads the address of the adjacent slot `0x5788118`, then `mov (%r8),%rdi` loads the window's input from that slot, then the call. The caller reads the slot immediately after the window's store target; no relationship between the two slots is claimed beyond their adjacency.

### Body behavior: one compare, one shift, one store, no calls

Decoded from the FDE start, the window takes its input in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5521d10` | `endbr64` | Landing pad |
| `0x5521d14` | `mov $0xffffffffffffffff,%rax` | Default result: all ones |
| `0x5521d1b` | `cmp $0xffffffffffffffff,%rdi` | Full-width test for -1 |
| `0x5521d1f` | `je 0x5521d2f` | -1 path skips the shift |
| `0x5521d21` | `mov $0x1,%eax` | Shift base |
| `0x5521d26` | `mov %edi,%ecx` | Shift count = low byte of input |
| `0x5521d28` | `shl %cl,%rax` | Shift by the low byte, count masked to 6 bits |
| `0x5521d2b` | `sub $0x1,%rax` | Mask = shifted value minus one |
| `0x5521d2f` | `mov %rax,0x2663da(%rip)` | Store to global at `0x5788110` |
| `0x5521d36` | `ret` | |

The rule, in full:

- If `rdi == -1` (the full 64-bit value, not merely a low byte of `0xff`), the stored value is `-1` (all 64 bits set).
- Otherwise the stored value is `(1 << (rdi & 0xff & 63)) - 1`, because x86-64 masks the `shl` count to 6 bits. Concretely: input 0 stores 0; input 1 stores 1; input 63 stores `0x7fffffffffffffff`; input 64 stores 0 (count masks to 0); input 65 stores 1; input 127 stores `0x7fffffffffffffff` (count masks to 63); input 255 stores `0x7fffffffffffffff` (count masks to 63) — but only because 255 != -1 as a full 64-bit value, so the special case does not fire.
- The `rdi == -1` special case exists precisely because the low byte of -1 is `0xff`, which would otherwise mask to 63 and store `0x7fffffffffffffff` instead of all ones. The special case is a full-width `cmp` against `0xffffffffffffffff`, not a low-byte test: an input such as `0x1ff` (low byte `0xff`, value not -1) takes the shift path and stores `0x7fffffffffffffff`, not -1.
- The store target `0x5788110` lies in `.data` (`[0x577a660, 0x57882f0)`), so the file holds an initial value there: `0xffffffffffffffff`. That file value is observed, not claimed as the runtime value; the global's meaning is unknown and not claimed. The checker locks the RIP-relative displacement and the file value, not any meaning.

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start |
| --- | --- | --- |
| `0x54b9c3f` | `[0x54b9b60, 0x54b9f1d)` | Yes, linear disassembly from FDE start |

The call site's 5-byte `e8` + rel32 sequence is locked by the checker, and its target resolves exactly to `0x5521d10`.

### No scout correction needed

Every scouted element verified exactly: FDE range, padding count, all ten instructions, the store displacement and target, the single caller, and the shift-masking caveat. One clarification added by the builder: the scout note did not state the store target's section; the target `0x5788110` lies in `.data`, not `.bss`, and its file value is `0xffffffffffffffff`.

## Inferences

- The "bitmask builder" label is an inference from the shift-minus-one shape writing a global. It is kept separate from the observed store rule.
- The mask is a low-bits mask: `(1 << n) - 1` has exactly its low `n` bits set (for `n` in 0..63), and the -1 case has all bits set.

## Unknowns

- The global's runtime meaning, and what kind of quantity the input is.
- The window's source-level name, type, and component owner.
- The caller's purpose beyond its call site and argument setup.
- Whether any caller relies on the stored value beyond the retained call site.

## Limits

- No stdlib type, source-level function, global meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
