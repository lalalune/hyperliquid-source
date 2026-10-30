# foundation-range-test-94: what does the global range-membership window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window, its two int3 padding bytes, four incoming direct calls with their caller FDEs, and the exact low-byte range-membership rule.
- Excluded: the globals' runtime values and meaning, the callers' behavior beyond their call sites and result use, the next FDE's two-pointer comparison, other range helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two global loads, two unsigned setcc instructions, one AND, no calls, no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5520e00`, no open pull request title mentions it or range-test, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), or byte-range-select packets.

This window is bound **alone**. The next FDE at `0x5520e20` is a two-pointer range comparison using the same two globals; it is a related but separate window and is never bound here, never as a pair, and no census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_range_test.py --check research/work-items/foundation-range-test-94/evidence.json
python3 -m unittest tests.test_foundation_range_test -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5520e00 --stop-address=0x5520e20 artifacts/node/94/hl-node
objdump -d --start-address=0x55184c0 --stop-address=0x55184d8 artifacts/node/94/hl-node
objdump -d --start-address=0x5518500 --stop-address=0x5518518 artifacts/node/94/hl-node
objdump -d --start-address=0x5518820 --stop-address=0x5518835 artifacts/node/94/hl-node
objdump -d --start-address=0x5518860 --stop-address=0x5518875 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site regions of the four caller FDEs (prologue through call); the full caller FDEs are `[0x55184c0, 0x55184f9)`, `[0x5518500, 0x5518539)`, `[0x5518820, 0x5518851)`, and `[0x5518860, 0x5518891)`, and only those regions are claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2c9074`, the next FDE at `0x2c9088`, and the four caller FDEs at `0x2c7e30`, `0x2c7e64`, `0x2c7f74`, and `0x2c7fa8`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c9074` describes `[0x5520e00, 0x5520e1e)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5520e1d` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x5520e20`, only because two `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those two padding bytes, and the checker locks the 30-byte body and the padding separately. The next FDE starts exactly at `0x5520e20`.
- No relocation of any type in `.rela.dyn` maps a slot to `0x5520e00`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly four direct `e8` calls to the window, each subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- Each caller consumes the result with `test %al,%al` immediately after the call, then a conditional jump. The callers' full behavior and the meaning of their arguments are not closed here.

### Body behavior: two globals, two unsigned tests, one AND, no calls

Decoded from the FDE start, the window takes a candidate value in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5520e00` | `endbr64` | Landing pad |
| `0x5520e04` | `mov 0x479915(%rip),%rdx` | Load hi global from `.bss` slot `0x599a720` |
| `0x5520e0b` | `cmp 0x47991e(%rip),%rdi` | Compare candidate against lo global at `.bss` slot `0x599a730` |
| `0x5520e12` | `setae %al` | al = 1 iff candidate >= lo (unsigned) |
| `0x5520e15` | `cmp %rdx,%rdi` | Compare candidate against hi global |
| `0x5520e18` | `setb %cl` | cl = 1 iff candidate < hi (unsigned) |
| `0x5520e1b` | `and %ecx,%eax` | Membership bit = al AND cl |
| `0x5520e1d` | `ret` | |

The rule, in full:

- Let `lo = mem[0x599a730]` and `hi = mem[0x599a720]`, both read from `.bss` at call time. Both comparisons are unsigned (`setae`/`setb`).
- The **low byte** of the return value is 1 if and only if `lo <= rdi < hi`, else 0.

### Precision correction over the scout note: low byte only

The scout note described this window as "return 1 iff lo <= rdi < hi, else 0". The retained bytes show that description is imprecise in one respect: **no instruction in the window zeroes eax or ecx before the setcc pair**, so only the low byte of the return value is the membership bit. The upper bytes of rax are the AND of whatever the caller left in the upper bytes of eax and ecx, and are not determined by this window. This packet therefore claims the low-byte rule only. The observation that all four callers consume the result with `test %al,%al` is consistent with low-byte-only use, and is recorded as caller behavior, not as a claim about the window's full return value.

### Globals: slots locked, values and meaning unknown

- The hi slot `0x599a720` and lo slot `0x599a730` both lie in `.bss` (`[0x5788300, 0x59b0e80)`), so the file holds no values for them; their runtime values are not claimed. The checker locks the two RIP-relative displacements and the comparison order, not any value.
- The slot order matters and is not symmetric: the first comparison tests the candidate against `0x599a730` (the lo bound), the second against `0x599a720` (the hi bound). Swapping the two slots would invert the interval, so both displacements are locked separately.
- The next FDE at `0x5520e20` (81 bytes) is a two-pointer range comparison that reads the same two globals and combines per-pointer membership bits. It is observed only to establish that it is a different window; its rule is not bound here.

Checked edges from the decoded rule (symbolic lo/hi, since concrete values are unknown):

- candidate == lo → low byte 1; candidate == hi - 1 → low byte 1.
- candidate == hi → low byte 0; candidate == lo - 1 → low byte 0; candidate above hi → low byte 0.
- Degenerate lo == hi → low byte 0 for every candidate; inverted lo > hi → low byte 0 for every candidate (both conditions cannot hold at once).

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start |
| --- | --- | --- |
| `0x55184d3` | `[0x55184c0, 0x55184f9)` | Yes, linear disassembly from FDE start |
| `0x5518513` | `[0x5518500, 0x5518539)` | Yes, linear disassembly from FDE start |
| `0x5518830` | `[0x5518820, 0x5518851)` | Yes, linear disassembly from FDE start |
| `0x5518870` | `[0x5518860, 0x5518891)` | Yes, linear disassembly from FDE start |

Each call site's 5-byte `e8` + rel32 sequence is locked by the checker, and each target resolves exactly to `0x5520e00`.

## Inferences

- The "global range-membership test" label is an inference from the two-global, two-unsigned-test, one-AND shape. It is kept separate from the observed low-byte rule.
- The interval is half-open (`lo <= x < hi`) by the unsigned test pair, not by any claimed convention about the globals.

## Unknowns

- The globals' runtime values and meaning, and what kind of quantity the candidate is.
- The window's source-level name, type, and component owner.
- The callers' purposes beyond their call sites and `test %al,%al` result use.
- Whether any caller relies on the upper bytes of the return value (no caller in the retained set reads them, but the full caller set is not a complete census).

## Limits

- No stdlib type, source-level function, global meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
