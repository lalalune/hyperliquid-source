# foundation-twin-widen-94: two near-identical windows differing only in element size

- Component: `foundation`, a bounded part of its first time/quantity helper mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about two target instruction windows and their call edges; no source-level name or element type is claimed for either window.
- Included: the two 94-byte FDE windows, their two int3 padding bytes each, the shared routine's FDE record (body not decoded), the clamp arithmetic, and the error-arm call edge through its relocated slot.
- Excluded: the shared routine body at `0x151f160`, the error-arm target body at link-time VA `0x1346068`, any caller of either window, other widen-like windows, all #115 addresses, target execution, Rust reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds two complete, independently disassembled FDE windows that are byte-identical except at exactly three offsets, and follows both of their call edges to the same shared routine and the same error-arm slot. It establishes a concrete small entrypoint for further reconstruction without declaring either window's source-level identity.

This pair was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x151f0a0` or `0x151f100`, and no open pull request title mentions either address or twin/widen for this area. The windows overlap nothing in the hour packet (`0x14509f0`), the days packet (`0x1450810`), the secs-f64 packet (`0x1450a60`), or the millis packet's calendar helper (`0x151f6f0`–`0x151f86a`).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu), GnuPG 2.4.4. The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_twin_widen.py --check research/work-items/foundation-twin-widen-94/evidence.json
python3 -m unittest tests.test_foundation_twin_widen -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x151f0a0 --stop-address=0x151f160 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `twin.objdump.txt` file retains complete disassembly of both windows (the shared routine body is excluded). The `twin.frames.txt` file retains excerpts selecting the CIE and the FDEs at `.eh_frame` section offsets `0x14f5c` (first window), `0x14f88` (second window), and `0x14fb4` (shared routine). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The binary is a PIE (ELF type DYN, stripped); section headers map `.text` with file offset = VA - `0x1000` and `.got` with file offset = VA - `0x2000`. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry and FDE extent

- `.eh_frame+0x14f5c` describes `[0x151f0a0, 0x151f0fe)`, 94 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- `.eh_frame+0x14f88` describes `[0x151f100, 0x151f15e)`, 94 bytes, with the same agreement.
- Two `int3` bytes (`0xcc`) follow each window before the next FDE start (`0x151f0fe`–`0x151f0ff`, then `0x151f15e`–`0x151f15f`). The padding is locked separately from the FDE bodies.
- `.eh_frame+0x14fb4` describes the shared routine `[0x151f160, 0x151f238)`. Its body is not decoded in this packet.

### Body behavior: one doubling, one clamp, one shared call, one flag arm

Both windows decode identically except where noted. The first window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x151f0a0` | `push r14; push rbx; sub $0x18,%rsp` | Prologue, 24-byte stack slot |
| `0x151f0a7` | `mov %rdi,%rbx` | Input struct pointer saved |
| `0x151f0aa` | `mov (%rdi),%rsi` | Length field into `rsi` |
| `0x151f0ad` | `lea (%rsi,%rsi,1),%rax` | Doubled length |
| `0x151f0b1` | `cmp $0x5,%rax` | Clamp comparison |
| `0x151f0b5` | `mov $0x4,%r14d` | Floor value 4 |
| `0x151f0bb` | `cmovae %rax,%r14` | Count = doubled length if >= 5, else 4 |
| `0x151f0bf` | `mov 0x8(%rdi),%rdx` | Second input field into `rdx` |
| `0x151f0c3` | `mov %rsp,%rdi` | Stack out-slot as first argument |
| `0x151f0c6` | `mov $0x4,%r8d` | Element size 4 (second window: 8) |
| `0x151f0cc` | `mov %r14,%rcx` | Count as fourth argument |
| `0x151f0cf` | `call 0x151f160` | Shared routine |
| `0x151f0d4` | `cmpl $0x1,(%rsp)` | Out-slot flag test |
| `0x151f0d8` | `je 0x151f0ee` | Flag 1 goes to the error arm |
| `0x151f0da` | `mov 0x8(%rsp),%rax` | Out-slot pointer |
| `0x151f0df` | `mov %rax,0x8(%rbx)` | Store pointer back into the input struct |
| `0x151f0e3` | `mov %r14,(%rbx)` | Store count back into the input struct |
| `0x151f0e6` | `add $0x18,%rsp; pop %rbx; pop %r14; ret` | Epilogue |
| `0x151f0ee` | error arm (see below) | Indirect call, then `int3` padding |

The shared call passes, in SysV order: `rdi` = stack out-slot, `rsi` = original (undoubled) length, `rdx` = second input field, `rcx` = count, `r8d` = element size. Whether the shared routine reads all five arguments is not decoded here; the register facts themselves are retained.

The clamp boundary values, computed from the branch (not assumed):

| Input length | Doubled | Count stored |
| --- | --- | --- |
| 0, 1, 2 | 0, 2, 4 | 4 |
| 3, 4 | 6, 8 | 6, 8 |

Because the doubled value is always even, the `>= 5` comparison and a `max(4, doubled)` reading agree on every input; the packet states the comparison as decoded and the equivalence as arithmetic, not as a recovered source expression.

The error arm loads the out-slot pointer and the out-slot second field into `rdi` and `rsi`, then calls indirectly through slot `0x576dfb8`. The slot carries an `R_X86_64_RELATIVE` relocation with addend link-time VA `0x1346068`, and its stored file bytes are zero. The addend address is itself an FDE start (`[0x1346068, 0x134607d)`), but that routine's body is not decoded here and no runtime target is named: the binary is a PIE, so the runtime address is load-base-relative.

### The twin difference, exactly

Byte comparison of the two 94-byte windows finds exactly three differing offsets:

| Window offset | First window | Second window | Cause |
| --- | --- | --- | --- |
| `0x28` | element-size immediate 4 | element-size immediate 8 | The only semantic difference |
| `0x30` | shared-call displacement `0x8c` | shared-call displacement `0x2c` | Same target `0x151f160`; sites sit `0x60` apart |
| `0x5a` | indirect-call displacement `0x424eeba` | indirect-call displacement `0x424ee5a` | Same slot `0x576dfb8`; sites sit `0x60` apart |

Both call displacements resolve to the same targets, verified by RIP-relative arithmetic in the checker, not by string matching.

## Inferences and unknowns

- **Claimed:** two near-identical windows differing only in element size, sharing one routine and one error-arm slot. That claim is fully grounded in the retained bytes, FDE records, and relocation record above.
- **Not claimed:** any element type, any standard-library or source-level name, and any behavior of the shared routine or the error-arm target. The disassembly listing's symbol labels are nearest-symbol artifacts (a `@@Base-0x...` suffix means the label is that far from the window start, not the window's name) and are not identifications.
- The input struct's other fields, the shared routine's argument use, the meaning of the out-slot flag value 1, and the callers of either window are not closed. No incoming-call census is attempted in this packet.
- The shared routine's FDE extent and the error-arm slot's relocation are locked, but neither callee body is decoded; a future packet may decode one of them without changing this packet's claim.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, element-size immediates, or clamp immediates;
- changed FDE extent, shared-call or indirect-call displacement, or flag-branch target;
- changed error-arm slot relocation or stored slot bytes;
- changed FDE padding bytes.

Structural mutations deliberately bypass only the digest gate in the test helper, so they exercise downstream checks instead of all failing at SHA-256. The command-line tool always authenticates the complete target first.

**No progress gate requested.** Foundation's gates and generated progress files stay unchanged. The denominator here is two bounded windows / one shared routine / one error-arm slot, not all widen-like helpers. Next question: decode the shared routine at `0x151f160` far enough to state its argument use, or decode the error-arm target at link-time VA `0x1346068`, before reconstructing Rust.
