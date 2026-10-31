# foundation-strided-array-sum-loop-94: what does the strided-array sum loop window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 77-byte FDE window with one padding byte, the strided-array sum loop rule with its exact fields and wrapping arithmetic, the exact incoming-call scan result (three direct sites), the zero naming relocation slots, and the stride-pattern uniqueness result.
- Excluded: what the table holds, what the count field denotes, what the index selects, what consumes the returned sum, any wider stride-loop family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a do-while loop summing `1 << count` qwords at a fixed `0xce40` stride plus an index offset, with three direct callers and no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x52cfe00`, no open pull request title mentions it or "strided", and its bytes overlap nothing in packets #1–#117.

## Scout note

The round-22 scout note listed this window (ranked #1) with FDE `[0x52cfe00, 0x52cfe4d)`, 77 bytes, 1 padding byte, three direct callers (FDEs `0x52cfe60`, `0x52d01e0`, `0x52d5a00`), zero naming relocation slots, the `0xce40`-stride add occurring exactly once in all of `.text`, and a full claimed-body byte-compare top match of only 17/77 (vs `0x4fec860`). Every element verified exactly; no scout correction was needed.

## Caveats, stated head-on

- **Twin guard, stated head-on (mandatory).** Full claimed-body byte-compare top match is only 17/77 vs `0x4fec860` — and `0x4fec860` disassembles as a linked-list / hash-bucket search with div, a completely different rule (the shared bytes are common opcodes, not a shared body). NOT a twin. Nearest claimed packet `0x52ca970` (packet #109, eight-byte binary search) is `0x5090` away, but distance is not the guard: search vs strided sum are different rules, and the byte-compare above is the operative guard.
- **Stride uniqueness, stated plainly.** The `0xce40`-stride add bytes (`49 81 c0 40 ce 00 00`) occur exactly once in all of `.text`, at `0x52cfe2b` inside this window. This loop is not part of a stride-loop population; the checker locks that uniqueness, so a second occurrence anywhere would fail the check.
- **Provenance, stated plainly.** This window was found in the round-22 general slice, NOT in any peer lane. The new peer wave's lanes themselves yielded no rankable easy window besides a region neighbour elsewhere; this packet does not claim peer-lane coverage.
- **Field-meaning caveat.** What the table at `[rdi+0x60]` HOLDS, what the `[rdi+0x68]` count field DENOTES, and what the index SELECTS are explicitly unclaimed. The checker locks only the literal arithmetic: sum over `base + i*0xce40 + index*8` for `i = 0..(1 << (field & 0x3f))-1`, wrapping mod 2^64.
- **Loop-shape caveat.** The loop always executes at least once: the counter is incremented before the first compare, and the count `1 << x` is at least 1 for every shift amount the hardware permits (cl masked to 6 bits). There is no zero-iteration path in the bytes, and none is claimed.
- **Caller census caveat.** The three direct callers come from a byte-pattern scan for `e8` sites whose rel32 lands on the window start. That scan is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_strided_array_sum_loop.py --check research/work-items/foundation-strided-array-sum-loop-94/evidence.json
python3 -m unittest tests.test_foundation_strided_array_sum_loop -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x52cfe00 --stop-address=0x52cfe4e artifacts/node/94/hl-node
objdump -d --start-address=0x52cfe60 --stop-address=0x52cfea2 artifacts/node/94/hl-node
objdump -d --start-address=0x52d01e0 --stop-address=0x52d0485 artifacts/node/94/hl-node
objdump -d --start-address=0x52d5a00 --stop-address=0x52d5fe5 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its one padding byte. The `caller.objdump.txt` file retains complete disassembly of the three caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2acc94` (this window), `0x64bc40` (the next FDE), `0x64bc10`, `0x64bd94`, `0x64c26c` (the caller FDEs), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2acc94` describes `[0x52cfe00, 0x52cfe4d)`, 77 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- One `int3` byte follows: the next FDE starts exactly at `0x52cfe4e` (record at `.eh_frame+0x64bc40`, range to `0x52cfe5e`). The unwind-index stride is therefore 78 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- Three `int3` bytes precede the window: the previous FDE ends at `0x52cfdfd`. That gap is padding, not code, and the checker locks it too.
- The window opens with `endbr64`, followed immediately by the index zero-extension — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x52cfe00`.

- Offset `0x00`: `endbr64` — entry.
- Offset `0x04`: `mov %esi,%esi` — index zero-extended to 64 bits.
- Offset `0x06`: `xor %r8d,%r8d` — stride cursor init to 0.
- Offset `0x09`: `xor %edx,%edx` — loop counter init to 0.
- Offset `0x0b`: `xor %r9d,%r9d` — sum init to 0.
- Offset `0x0e`: `shl $0x3,%rsi` — index times 8.
- Offset `0x12`: `mov $0x1,%r10d` — shift-one init (the value shifted to form the count).
- Offset `0x18`: `nopl 0x0(%rax,%rax,1)` — 8-byte loop alignment nop.
- Offset `0x20` (loop head): `mov 0x60(%rdi),%rax` — table base load.
- Offset `0x24`: `add $0x1,%rdx` — counter increment (before the first compare: do-while shape).
- Offset `0x28`: `add %r8,%rax` — stride cursor add.
- Offset `0x2b`: `add $0xce40,%r8` — stride cursor advance (the unique stride add).
- Offset `0x32`: `add %rsi,%rax` — index offset add.
- Offset `0x35`: `mov (%rax),%rax` — element load.
- Offset `0x38`: `add %rax,%r9` — sum add (wrapping).
- Offset `0x3b`: `mov %r10,%rax` — shift-one move.
- Offset `0x3e`: `mov 0x68(%rdi),%ecx` — count field load (32-bit).
- Offset `0x41`: `shl %cl,%rax` — count = 1 << (field & 0x3f); the hardware masks cl to 6 bits for the 64-bit shift.
- Offset `0x44`: `cmp %rax,%rdx` — counter vs count.
- Offset `0x47`: `jb 0x52cfe20` — loop while counter < count (unsigned).
- Offset `0x49`: `mov %r9,%rax` — return move.
- Offset `0x4c`: `ret` — single ret.

### Decoded rule

With `base = [rdi+0x60]`, `index = esi` zero-extended, and `count = 1 << ([rdi+0x68] & 0x3f)`:

```
sum = 0
for i = 0..count-1:
    sum = (sum + [base + i*0xce40 + index*8]) mod 2^64
return sum
```

No field is written. No call occurs inside. The only transfer is the backward conditional loop branch. The count is at least 1 for every field value, so the loop body always runs at least once.

### Incoming calls and data edges

- Direct `e8` call sites whose rel32 lands on the window start, found by a full-`.text` byte-pattern scan (70,370,352 bytes): exactly three — `0x52cfe7e` (inside FDE `[0x52cfe60, 0x52cfea2)`), `0x52d0265` (inside FDE `[0x52d01e0, 0x52d0485)`), `0x52d5b03` (inside FDE `[0x52d5a00, 0x52d5fe5)`). Each is boundary-confirmed inside its own caller FDE and independently resolved to the window start by objdump's caller disassembly. The scan is not a complete xref census.
- Relocation slots: zero `R_X86_64_RELATIVE` records in any `.rela.*` section name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). No meaning is claimed from the absence.
- Stride uniqueness: the stride-add byte pattern `49 81 c0 40 ce 00 00` occurs exactly once in all of `.text`, at `0x52cfe2b` inside this window.

## Inferences

- The "strided-array sum loop" label is an inference from the literal rule (a strided sum over a table with a fixed stride and an index offset). It is kept separate from the observed arithmetic above.
- Nothing is inferred about the table's element type, the count field's unit, or the callers' purpose. In particular, the `0xce40` stride is not claimed to be a struct size, a page multiple, or anything else: it is the literal constant the bytes add.

## Unknowns

- What the table holds and who fills it.
- What the count field counts in domain terms, and whether the index selects a column, a field, or something else.
- Whether the three callers pass related or unrelated tables.
- Any source-level name, type, or ownership (library vs private) for this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern call scan is not a complete xref census, and the zero-slot result does not identify the window's provenance.
- The stride-uniqueness result covers the exact 7-byte stride-add pattern only; other stride idioms elsewhere are out of scope.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
