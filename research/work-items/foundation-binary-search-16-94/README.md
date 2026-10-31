# foundation-binary-search-16-94: what does the binary-search window over 16-byte entries compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 106-byte FDE window with six padding bytes, the lower-bound binary-search rule it implements, the exact incoming-call scan result (fourteen direct sites in ten caller FDEs), and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the callers, whether the actual table is sorted, and any wider search-helper family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a sar-based midpoint loop over 16-byte entries that returns the first entry whose double-dereferenced key is greater than or equal to the search key (unsigned comparison), or the table end. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window is heavier than the recent single-gate packets (a loop, fourteen callers), and that weight is stated head-on rather than buried: it is bound because the rule locks exactly from its own bytes — every instruction at a fixed offset, every branch target on a retained instruction start, all fourteen call sites boundary-confirmed — not because it is small. No caller context is needed to state the rule, and none is claimed.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51cb570`, no open pull request title mentions it or binary-search-16, and its bytes overlap nothing in packets #1–#75.

## Scout note

The round-11 scout note listed this window (backup B4) with FDE `[0x51cb570, 0x51cb5da)`, 106 bytes, 6 padding bytes, fourteen direct callers with the first twelve boundary-confirmed, and no naming relocation. Every element verified exactly, and the boundary confirmation was strengthened to all fourteen sites by linear disassembly from each caller FDE start (the scout's "first 12" was the extent of its own check, not a claim about the remaining two). No numeric correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the fourteen direct sites are incoming calls from ten caller FDEs — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_binary_search_16.py --check research/work-items/foundation-binary-search-16-94/evidence.json
python3 -m unittest tests.test_foundation_binary_search_16 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51cb570 --stop-address=0x51cb5e0 artifacts/node/94/hl-node
objdump -d --start-address=0x51a5db0 --stop-address=0x51a5f09 artifacts/node/94/hl-node
objdump -d --start-address=0x51a9d80 --stop-address=0x51aa0c9 artifacts/node/94/hl-node
objdump -d --start-address=0x51aa570 --stop-address=0x51ab46c artifacts/node/94/hl-node
objdump -d --start-address=0x51ab640 --stop-address=0x51ac66f artifacts/node/94/hl-node
objdump -d --start-address=0x51afff0 --stop-address=0x51b0cb5 artifacts/node/94/hl-node
objdump -d --start-address=0x51b2620 --stop-address=0x51b38d2 artifacts/node/94/hl-node
objdump -d --start-address=0x51d02d0 --stop-address=0x51d056a artifacts/node/94/hl-node
objdump -d --start-address=0x51d0a20 --stop-address=0x51d0ab0 artifacts/node/94/hl-node
objdump -d --start-address=0x51d0ab0 --stop-address=0x51d1002 artifacts/node/94/hl-node
objdump -d --start-address=0x51ded50 --stop-address=0x51dfbb9 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its six padding bytes. The `caller.objdump.txt` file retains complete disassembly of all ten caller FDEs, from which the fourteen call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2a1170` (this window), `0x2a1184` (the next FDE, which is both the next record in `.eh_frame` order and the address-order successor), `0x29f444`, `0x6382dc`, `0x638324`, `0x638378`, `0x6387b8`, `0x63880c`, `0x6394fc`, `0x2a1758`, `0x2a1784`, `0x639e8c` (the ten caller FDEs), plus the shared CIEs at offsets `0` and `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a1170` describes `[0x51cb570, 0x51cb5da)`, 106 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x51cb5d8` is inside the FDE).
- Six `int3` bytes (`0xcc`) follow at `0x51cb5da`–`0x51cb5df`, and the next FDE starts exactly at `0x51cb5e0` (record at `.eh_frame+0x2a1184`, range to `0x51cb5ec`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately. Here the next record in `.eh_frame` order is also the address-order successor, unlike packets where the two differ.
- The window opens with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x223770`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: lower-bound binary search over 16-byte entries, no calls, five branches

Inputs: `rdi` = struct pointer, `rsi` = search key. Fields read: `lo = [rdi+0xad8]`, `hi = [rdi+0xae0]` (two adjacent qword fields, presumably the table bounds). Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x51cb570` | `endbr64` | Landing pad |
| `0x51cb574` | `mov 0xad8(%rdi),%r8` | `lo` loaded |
| `0x51cb57b` | `mov 0xae0(%rdi),%rax` | `hi` loaded |
| `0x51cb582` | `sub %r8,%rax` | Byte span `hi - lo` |
| `0x51cb585` | `mov %rax,%rdx` | Span copied |
| `0x51cb588` | `sar $0x4,%rdx` | Entry count = span sar 4 |
| `0x51cb58c` | `test %rax,%rax` | Span sign test |
| `0x51cb58f` | `jle 0x51cb5c3` | Non-positive span → return `lo` |
| `0x51cb591` | `nopl 0x0(%rax)` | Loop alignment padding (7 bytes, reached only by fall-through) |
| `0x51cb598` | `mov %rdx,%rcx` | Count copied (loop head) |
| `0x51cb59b` | `sar $1,%rcx` | Midpoint index = count sar 1 |
| `0x51cb59e` | `mov %rcx,%rax` | Midpoint copied |
| `0x51cb5a1` | `shl $0x4,%rax` | Midpoint scaled by 16 |
| `0x51cb5a5` | `add %r8,%rax` | Midpoint entry pointer |
| `0x51cb5a8` | `mov (%rax),%rdi` | Entry's first qword → pointer |
| `0x51cb5ab` | `mov (%rdi),%rdi` | Key cell's first qword → key |
| `0x51cb5ae` | `cmp %rsi,(%rdi)` | Compare key against search key |
| `0x51cb5b1` | `jae 0x51cb5d0` | Key >= search key (unsigned) → lower half |
| `0x51cb5b3` | `sub %rcx,%rdx` | Upper-half count: count - mid |
| `0x51cb5b6` | `lea 0x10(%rax),%r8` | Upper-half lo: entry + 16 |
| `0x51cb5ba` | `sub $0x1,%rdx` | Upper-half count minus one |
| `0x51cb5be` | `test %rdx,%rdx` | Remaining-count test |
| `0x51cb5c1` | `jg 0x51cb598` | Still entries left → loop |
| `0x51cb5c3` | `mov %r8,%rax` | Return current `lo` |
| `0x51cb5c6` | `ret` | Return |
| `0x51cb5c7` | `nopw 0x0(%rax,%rax,1)` | Return alignment padding (9 bytes, unreachable: follows `ret`, targeted by no branch) |
| `0x51cb5d0` | `test %rcx,%rcx` | Midpoint-zero test |
| `0x51cb5d3` | `je 0x51cb5c3` | Midpoint zero → return `lo` |
| `0x51cb5d5` | `mov %rcx,%rdx` | Lower-half count = mid |
| `0x51cb5d8` | `jmp 0x51cb598` | Lower half → loop |

Rule, stated exactly: let `span = hi - lo` (64-bit wrap, read signed for the test and the shift). If `span <= 0` signed, return `lo` without reading any entry. Otherwise `count = span sar 4`, and the loop maintains the range `[lo, lo + count*16)`: `mid = count sar 1`, `entry = lo + mid*16`, `key = [[entry]]`; if `key >= rsi` unsigned, then `mid == 0` returns `lo`, else `count = mid` and the loop repeats; if `key < rsi` unsigned, then `lo = entry + 16`, `count = count - mid - 1`, and the loop repeats only if `count > 0`, else `lo` is returned. The returned pointer is the first entry whose key is `>= rsi` (unsigned), or the table end `hi` when every probed key is `< rsi`, assuming a well-formed span (a multiple of 16) and ascending keys.

Quirks, stated not smoothed over:

- The entry's second qword is never read. Only the first qword (a pointer) and that pointer's first qword (the key) participate.
- The comparison is unsigned (`jae`). A key with the high bit set compares above every small positive key; a signed reading would differ and is not what the bytes do.
- For a positive span that is not a multiple of 16, `count` truncates (`span sar 4`) and the loop still probes the entry at `lo` once when `count` is 0: key `>= rsi` returns `lo`, else `lo + 16` (past `hi` for such a span). A malformed-table quirk, recorded as observed.
- The `nopl` at `0x51cb591` is alignment padding before the loop head, reached only by fall-through (never a branch target). The `nopw` at `0x51cb5c7` follows a `ret` and is targeted by no branch, so it is unreachable padding. Both are locked as bytes, not as behavior.
- `rdi` is clobbered inside the window (reused as scratch for the entry pointer and key), so no argument register survives the call.

### Incoming calls: fourteen direct sites in ten caller FDEs, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly fourteen direct `e8` sites whose rel32 lands on the window start, each confirmed as an instruction start by linear disassembly from its caller FDE start:

| Call site | Caller FDE | Setup immediately before the call (locked as bytes) |
| --- | --- | --- |
| `0x51a5dce` | `0x51a5db0..0x51a5f09` | `mov 0x18(%rbp),%rdi; lea 0x100(%rbp),%r13` |
| `0x51a9e52` | `0x51a9d80..0x51aa0c9` | `mov %rbx,%rsi; mov %r13,%rdi` |
| `0x51aa70a` | `0x51aa570..0x51ab46c` | `mov %rbx,%rsi; mov %r14,%rdi` |
| `0x51ab681` | `0x51ab640..0x51ac66f` | `mov %rax,0xb8(%rsp); xor %eax,%eax` |
| `0x51b0165` | `0x51afff0..0x51b0cb5` | `mov %r14,%rsi; mov %r13,%rdi` |
| `0x51b2902` | `0x51b2620..0x51b38d2` | `jb 0x51b3642; xor %esi,%esi` |
| `0x51d03a5` | `0x51d02d0..0x51d056a` | `mov %rbx,%rsi; mov %rbx,-0xa8(%rbp)` |
| `0x51d0a43` | `0x51d0a20..0x51d0ab0` | `lea 0x40(%rbx),%rdi; mov %rbp,%rsi` |
| `0x51d0bba` | `0x51d0ab0..0x51d1002` (shared) | `mov %r12,%rdi; mov %r15,%rsi` |
| `0x51d0be1` | `0x51d0ab0..0x51d1002` (shared) | `mov %r12,%rdi; mov %r15,%rsi` |
| `0x51d0c08` | `0x51d0ab0..0x51d1002` (shared) | `mov %r12,%rdi; mov %r15,%rsi` |
| `0x51d0c3e` | `0x51d0ab0..0x51d1002` (shared) | `mov %r12,%rdi; mov %r15,%rsi` |
| `0x51d0ce2` | `0x51d0ab0..0x51d1002` (shared) | `mov %r12,%rdi; mov %r13,%rsi` |
| `0x51dee26` | `0x51ded50..0x51dfbb9` | `mov %rbx,0x60(%rsp); mov %rbx,0x98(%rsp)` |

Five sites share one caller FDE (`0x51d0ab0..0x51d1002`); the other nine sites sit in nine distinct caller FDEs. Setup varies per site and is locked as bytes only — no caller purpose is claimed, and the byte-pattern scan is explicitly not a complete xref census (indirect calls, tail jumps, and PLT references are out of scope).

### Data edges

- No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` = 80,300 entries).
- The window's FDE uses CIE at offset `0` (`zR`, pcrel sdata4). Seven caller FDEs use a second CIE at offset `0x6205d0` (`zPLR`, same pcrel-sdata4 FDE encoding); both CIE records are locked raw in the checker.
- Nearest claimed window: pointer-sum gate `0x521cc40` (packet #47), `0x516d0` away.

## Inferences

- The "binary search over 16-byte entries" label is an inference from the loop shape (sar midpoint, 16-byte stride, unsigned key compare, lower-bound return). The observed rule above stands without it.
- The two adjacent struct fields at `+0xad8`/`+0xae0` are read as the table bounds; whether they are literally begin/end pointers of one array, and what the entries point at, is not established from this window alone.
- The lower-bound reading assumes ascending keys. If the actual table is not sorted ascending, the walk returns whatever its comparisons produce, not a true lower bound. No sortedness claim is made.

## Unknowns

- The source-level function, the struct type, the entry type, and the meaning of the second qword of each entry.
- The identity and purpose of all ten caller FDEs, and why five call sites share one caller.
- Whether any indirect caller or tail-jump reference to this window exists (outside the direct-`e8` scan).
- The contents of the actual table at runtime (never read from a live process; only the access pattern is bound).

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
