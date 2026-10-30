# foundation-twin-take-94: what do the twin take-from-pointer windows compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `main` `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about two target instruction windows and their data/call
  edges; their source-level names and types remain inferences. The claim is
  exactly "twin take helpers differing by inline-copy threshold" — nothing more.
- Included: the two FDE windows, their shared skeleton, their shared panic and
  drop call slots, the memcpy-slot copy of the first window, the inline copy
  of the second window, and a `.text` incoming-call scan (empty result).
- Excluded: the identities of the panic/drop/memcpy call targets, the meaning
  of the `[rsi+4] == 1` flag, the meaning of the panic argument slot's
  relocated value, any stdlib type or source-level function name, other take
  helpers, all #115 addresses, target execution, Rust reconstruction, and
  complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet connects two adjacent, structurally
identical windows through relocated slots to their call edges, and shows that
the only behavioral difference between them is how the taken value is copied
out: a large copy goes through a memcpy slot, a small copy is inlined. It
establishes a concrete small entrypoint for further reconstruction without
declaring the component mapped.

This window pair was checked for overlap before building: no work-item, tool,
or test in the tree mentions `0x14519c0` or `0x1451bf0`, and no open pull
request title mentions them or twin-take. Its bytes overlap nothing in the
hour, millis, duration-guards, days-to-date, secs-f64, twin-widen,
reserve-grow, twin-once-flag, set-once, days-seconds, or unwrap-guard packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu), GnuPG 2.4.4. The checker and
tests use Python's standard library only. No llvm-objdump, Ghidra, or Java
was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_twin_take.py --check research/work-items/foundation-twin-take-94/evidence.json
python3 -m unittest tests.test_foundation_twin_take -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14519c0 --stop-address=0x1451a20 artifacts/node/94/hl-node
objdump -d --start-address=0x1451bf0 --stop-address=0x1451c50 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `take1.objdump.txt` file retains complete disassembly of the first
window including its padding. The `take2.objdump.txt` file retains complete
disassembly of the second window. The `take.frames.txt` file retains excerpts
selecting the FDEs at `.eh_frame` section offsets `0xadd4` (first window),
`0xae24` (second window), and `0x2eeb8c` (the FDE starting exactly at the
second window's end, proving zero padding). The checker locks these raw FDE
records and their shared CIE, and reads their PC/range fields. It does not
add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extents, and the index-stride correction

- `.eh_frame+0xadd4` describes `[0x14519c0, 0x1451a19)`, 89 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 96 bytes, ending at
  `0x1451a20`, only because seven `int3` bytes (`0xcc`) pad the window after
  the FDE end. The stride is **not** the FDE extent; any description of this
  window as "96-byte FDE-bounded" would overstate the frame by those seven
  padding bytes, and the checker locks the 89-byte body and the padding
  separately.
- `.eh_frame+0xae24` describes `[0x1451bf0, 0x1451c50)`, 96 bytes. The next
  FDE starts exactly at `0x1451c50`, so this window has **no** padding: its
  FDE end is its stride end. The checker locks the following FDE's PC/range
  to prove this.
- A `R_X86_64_RELATIVE` relocation maps slot `0x566a7f8` to `0x14519c0` and
  slot `0x566a7d0` to `0x1451bf0`. The exact `.text` byte-pattern scan covers
  70,370,352 bytes. For `ff 15` / `ff 25` whose RIP target is either slot it
  finds zero candidates, and for `e8` targeting either window it finds zero
  candidates. Register-indirect references, other pointer paths, prefixes,
  and data sections are not a complete xref census: the windows may be
  reached through data pointers, and the slots themselves are retained as
  evidence of that possibility.

### Shared skeleton

Both windows execute the same skeleton, with only prologue/epilogue and copy
differences:

| Step | First window (`0x14519c0`) | Second window (`0x1451bf0`) |
| --- | --- | --- |
| Prologue | `push r14; push rbx; sub $0x268, %rsp` | `push rbx; sub $0x40, %rsp` |
| Load | `mov (%rdi), %rax` | `mov (%rdi), %rax` |
| Dereference | `mov (%rax), %rbx` | `mov (%rax), %rbx` |
| Zero | `movq $0, (%rax)` | `movq $0, (%rax)` |
| Null test | `test %rbx, %rbx; je panic` | `test %rbx, %rbx; je panic` |
| Flag test | `cmpb $1, 0x4(%rsi); je drop` | `cmpb $1, 0x4(%rsi); je drop` |
| Call | `call *(%rbx)` (vtable first slot) | `call *(%rbx)` (vtable first slot) |
| Copy | 0x268 bytes via memcpy slot | 0x38 bytes inline |
| Epilogue | `add $0x268, %rsp; pop rbx; pop r14; ret` | `add $0x40, %rsp; pop rbx; ret` |

The first window passes its stack buffer (`rsp`) as the call's `rdi`; the
second window passes `rsp+8` as the call's `rdi`. In both cases the call
writes the value into that buffer, and the copy that follows moves it to the
taken pointer `rbx`.

### Shared panic and drop arms

Both windows share the same two arms, reached by the same two branches:

| Arm | First window | Second window | Call edges |
| --- | --- | --- | --- |
| Panic | `0x1451a06` | `0x1451c3d` | `lea 0x566a808, %rdi; call *slot 0x576e470` |
| Drop | `0x1451a13` | `0x1451c4a` | `call *slot 0x576e868` |

The panic slot `0x576e470` is a `R_X86_64_RELATIVE` relocation to
`0x157a9f0`. The drop slot `0x576e868` is a `R_X86_64_RELATIVE` relocation
to `0x4eeb4c0`, inside the executable segment. The panic argument slot
`0x566a808` is itself a `R_X86_64_RELATIVE` relocation to `0x1f87cf`. All
three targets are left unnamed: their library ownership, behavior, and
non-returning properties are not closed. The `lea` loads the slot's address,
not its relocated contents.

### The copy difference (the twin claim)

- First window: after the vtable call, `mov $0x268, %edx; mov %rbx, %rdi;
  mov %r14, %rsi` (with `r14 = rsp`), then `call *slot 0x576dfe0`. That slot
  is a `GLOB_DAT` import relocation, not a `RELATIVE` one; its runtime value
  is supplied by the loader. The copied length equals the reserved stack
  buffer (0x268), and the frame's CFA offset (640 = 0x268 + 24) agrees.
- Second window: after the vtable call, three `movups` move 0x30 bytes from
  `rsp+8`, `rsp+0x18`, `rsp+0x28` to `(%rbx)`, `0x10(%rbx)`, `0x20(%rbx)`,
  and a `mov 0x38(%rsp), %rax; mov %rax, 0x30(%rbx)` moves the final 8 bytes.
  The total inline copy is 0x38 bytes, matching the buffer span `rsp+8` to
  `rsp+0x40`, and the frame's CFA offset (80 = 0x40 + 16) agrees.
- Correction to an early scout note: the scout note counted only the movups
  portion as 0x30 bytes. The retained bytes show the tail move extends the
  copy to 0x38. The checker locks the full 0x38, and the threshold claim uses
  0x38, not 0x30.

The threshold reading is deliberately narrow: the small copy is inlined and
the large copy goes through the memcpy slot. No size threshold constant is
recovered, and no claim is made about which sizes other take helpers use.

### A warning about objdump labels

GNU objdump prints these windows under labels derived from the nearest
symbol in the symbol table, with very large offsets (tens of megabytes).
Those labels are nearest-symbol arithmetic over a mostly stripped binary,
not recovered function names, and they are **not** used as evidence anywhere
in this packet. The retained disassembly keeps them only because it is raw
objdump output.

## Inferences and unknowns

- **Inferred:** these are twin take-from-pointer helpers, one for a large
  value and one for a small value, with the copy method chosen by size. The
  identical skeleton, shared arms, and copy-only difference support that
  label. The binary has no recovered symbol name here. Neither the
  source-level function names, the value types, the meaning of the `[rsi+4]
  == 1` flag, nor the identity of the vtable target is proven.
- The "take" reading (the loaded value is consumed and its slot zeroed)
  follows from the load-dereference-zero sequence, but the ownership
  semantics — what is taken, from whom, and what the zeroing guarantees —
  are not proven.
- The panic and drop arms are named only by their branch positions. Whether
  the panic arm returns, what the drop arm releases, and what the relocated
  panic argument points to are unknown.
- No incoming call sites were found by the `.text` scan. That does not prove
  the windows are uncalled: data-pointer paths (including the windows' own
  relocated slots) are outside the scan.
- The memcpy slot's runtime target is not decoded; only its import
  relocation kind (`GLOB_DAT`) and its call displacement are locked.

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
- changed skeleton bytes (load, dereference, zeroing, null test, flag test);
- changed branch displacements to the panic or drop arms;
- changed memcpy length or inline movups/tail-move bytes;
- changed FDE extent, stride padding, or relative relocation target;
- changed panic/drop/memcpy call displacement and an additional direct-call
  pattern;
- changed GLOB_DAT relocation for the memcpy slot;
- any incoming-call candidate appearing in the `.text` scan.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is two bounded windows,
not all take helpers. Next question: find the data-pointer paths that reach
these windows (starting from their relocated slots) before reconstructing
Rust, and attribute the shared panic/drop targets.
