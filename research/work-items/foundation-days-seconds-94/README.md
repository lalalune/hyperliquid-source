# foundation-days-seconds-94: what does the checked days-to-seconds window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call
  edges; its source-level name and types remain inferences.
- Included: the 70-byte FDE window, its ten int3 padding bytes, two incoming
  direct calls, the two outgoing callee calls, the two signed-overflow arms
  with their distinct call targets, and the shared argument value both arms load.
- Excluded: the two callee bodies at `0x15183e0` and `0x1518230`, the caller
  beyond its two call sites, the overflow-arm call targets' bodies at
  `0x157b4a0` and `0x157b480`, the data at the shared argument value
  `0x5671988` (its message or location record, if any, is not decoded here),
  other time conversions, all #115 addresses, target execution, Rust
  reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet connects two actual incoming calls to a
complete, independently disassembled FDE window, then follows its two
checked arithmetic operations to two distinct overflow arms. It establishes
a concrete small entrypoint for further reconstruction without declaring
the component mapped.

This window was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1518ca0`, no open pull request title mentions
it or days-to-seconds, and its bytes overlap nothing in the hour packet
(`0x14509f0`), the days-to-date packet (`0x1450810`), the seconds-as-f64
packet (`0x1450a60`), or any other claimed foundation window.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use
Python's standard library only. No llvm-objdump, Ghidra, or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_days_seconds.py --check research/work-items/foundation-days-seconds-94/evidence.json
python3 -m unittest tests.test_foundation_days_seconds -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1518ca0 --stop-address=0x1518cf0 artifacts/node/94/hl-node
objdump -d --start-address=0x1517a70 --stop-address=0x1517f00 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `seconds.objdump.txt` file retains complete disassembly of the window
including its padding. The `caller.objdump.txt` file retains complete
disassembly of the caller FDE window. The `seconds.frames.txt` file retains
excerpts selecting the FDEs at `.eh_frame` section offsets `0x148e8`
(this window), `0x147ac` (the caller), `0x14848` and `0x14864` (the two
callees), and `0x199b4` and `0x199d0` (the two overflow-arm targets).
The checker locks the window and caller FDE records and their shared CIE,
and reads their PC/range fields. It does not add a second general FDE
decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and the index-stride correction

- `.eh_frame+0x148e8` describes `[0x1518ca0, 0x1518ce6)`, 70 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 80 bytes, ending at
  `0x1518cf0`, only because ten `int3` bytes (`0xcc`) pad the window after
  the FDE end. The stride is **not** the FDE extent; any description of this
  window as "80-byte FDE-bounded" would overstate the frame by those ten
  padding bytes, and the checker locks the 70-byte body and the padding
  separately.
- The `.text` byte-pattern scan covers 70,370,352 bytes. For `e8` targeting
  the window it finds two candidates, `0x1517e43` and `0x1517eb5`, both
  subsequently visible as instruction starts in GNU disassembly from the
  caller FDE start. Register-indirect references, other pointer paths,
  prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x1517a70, 0x1517f00)`, 1,424 bytes. The two call
  sites are real direct calls; the caller's full behavior and its other
  arguments are not closed here.

### Body behavior: two calls, one multiply, one add, two overflow arms

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1518ca0` | `push rbp; push rbx; push rax` | Callee-saved saves, stack slot |
| `0x1518ca3` | `mov rdx,rbx` | Second input saved |
| `0x1518ca6` | `mov esi,ebp` | First input (low 32 bits) saved |
| `0x1518ca8` | `call 0x15183e0` | First callee, entry `rdi`/`rsi` |
| `0x1518cad` | `mov ebp,edi` | First input restored |
| `0x1518caf` | `mov rax,rsi` | First callee result as next argument |
| `0x1518cb2` | `call 0x1518230` | Second callee |
| `0x1518cb7` | `imul $0x15180,%rax` | Second result times 86400 |
| `0x1518cbe` | `jo 0x1518ccc` | Signed multiply overflow arm |
| `0x1518cc0` | `add rbx,rax` | Plus the saved second input |
| `0x1518cc3` | `jo 0x1518cd9` | Signed add overflow arm |
| `0x1518cc5` | `add $0x8,rsp; pop rbx; pop rbp; ret` | Result returned in `rax` |
| `0x1518ccc` | imul-overflow arm (see below) | Noreturn path, then second arm |
| `0x1518cd9` | add-overflow arm (see below) | Noreturn path, then `int3` padding |

The two overflow arms are distinct paths with distinct call targets, but
both load the same argument value before calling:

| Arm | VA | Argument | Call slot | Relocated target |
| --- | --- | --- | --- | --- |
| Multiply overflow | `0x1518ccc` | `rdi = 0x5671988` | `0x576e1b0` | `0x157b4a0` |
| Add overflow | `0x1518cd9` | `rdi = 0x5671988` | `0x576e118` | `0x157b480` |

Both slots are `R_X86_64_RELATIVE` relocations. After either arm's call
only the next arm or `int3` padding follows, consistent with noreturn
paths. The data at `0x5671988` is deliberately not decoded here: whether
it is a message, a location record, or something else is unknown, and no
panic text or source location is claimed for this window.

The multiply and the add are both signed operations checked with `jo`,
so each overflow arm fires exactly on signed overflow of its own
operation. When neither operation overflows, the window returns `rax`
unchanged: second callee result times 86400 plus the saved second input.

## Inferences and unknowns

- **Inferred:** this is a checked conversion helper whose second stage
  multiplies by 86400, the number of seconds in a day, and adds a saved
  input. Its 86400 multiplier, two-call shape, and two distinct signed
  overflow arms support that label. The binary has no recovered symbol
  name here. Neither the source-level function name, the input/output
  types, the meaning of either callee, nor the meaning of the saved second
  input is proven.
- The two callees are identified only as direct call targets with their
  own FDEs (`0x15183e0..0x151877c` and `0x1518230..0x15183d2`); their
  bodies, return types, and error behavior are not decoded.
- The two overflow-arm targets are identified only as relocated call
  targets with their own FDEs (`0x157b4a0..0x157b4b9` and
  `0x157b480..0x157b499`); their bodies and whether they return are not
  closed, beyond the noreturn-consistent layout that follows each call.
- The two incoming call sites are real direct calls, but the caller's
  full behavior, its other arguments, and whether other callers exist
  through register-indirect or data paths are not closed. The
  byte-pattern scan is not a complete xref census.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below. After the change, the new checker and the new unit
test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed multiplier byte or overflow-branch bytes;
- changed FDE extent, caller FDE record, or relative relocation target;
- changed callee or overflow-arm call displacement and argument target;
- changed incoming call bytes or call-pattern set;
- changed FDE padding bytes.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is one bounded window /
two call sites, not all time helpers. Next question: decode one of the two
callees far enough to say what the multiplied value is, before
reconstructing Rust.

[END USER CONTEXT: standing context files]
