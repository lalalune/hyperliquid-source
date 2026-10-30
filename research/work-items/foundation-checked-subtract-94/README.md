# foundation-checked-subtract-94: what does the checked 256-bit subtract window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 87-byte FDE window with nine padding bytes, the checked 256-bit subtract rule it implements, the unconditional minuend rewrite, the exact incoming-call scan result, and the absence of any relocation naming the window.
- Excluded: the meaning of the 256-bit values, the identity or purpose of the caller, and any wider arithmetic family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a four-word sub/sbb chain, a borrow-in trick built from `add $0xff,%al`, and a single success/failure branch that gates only the result copy and the flag value. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x2760a10`, no open pull request title mentions it or checked-subtract, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, chunk-equality, error-name, or tagged-copy packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_checked_subtract.py --check research/work-items/foundation-checked-subtract-94/evidence.json
python3 -m unittest tests.test_foundation_checked_subtract -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x2760a10 --stop-address=0x2760a70 artifacts/node/94/hl-node
objdump -d --start-address=0x2760040 --stop-address=0x2760a04 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its nine padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE at `0x2760040`, from which the three call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0xa0cd0` (this window) and `0x40fce8` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0xa0cd0` describes `[0x2760a10, 0x2760a67)`, 87 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x2760a66` is inside the FDE).
- Nine `int3` bytes (`0xcc`) follow at `0x2760a67`–`0x2760a6f`, and the next FDE starts exactly at `0x2760a70` (record at `.eh_frame+0x40fce8`, range 4262 bytes to `0x2761b16`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: four-word subtract with a borrow-in trick, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x2760a10` | `mov (%rsi),%rax` | Subtrahend word 0 |
| `0x2760a13` | `sub %rax,(%rdx)` | Minuend word 0 minus subtrahend word 0 |
| `0x2760a16` | `mov 0x8(%rsi),%rax` | Subtrahend word 1 |
| `0x2760a1a` | `sbb %rax,0x8(%rdx)` | Word 1 minus subtrahend word 1 and borrow |
| `0x2760a1e` | `mov 0x10(%rsi),%rax` | Subtrahend word 2 |
| `0x2760a22` | `sbb %rax,0x10(%rdx)` | Word 2 minus subtrahend word 2 and borrow |
| `0x2760a26` | `mov 0x18(%rdx),%r8` | Original minuend top word saved |
| `0x2760a2a` | `setb %al` | Low-word borrow (carry after the word-2 sbb) captured |
| `0x2760a2d` | `mov 0x18(%rsi),%rsi` | Subtrahend top word |
| `0x2760a31` | `mov %r8,%r9` | Top-word working copy |
| `0x2760a34` | `sub %rsi,%r9` | Top difference before borrow-in |
| `0x2760a37` | `add $0xff,%al` | Carry flag set to the low-word borrow (al 1 + 0xff wraps with CF 1; al 0 + 0xff leaves CF 0) |
| `0x2760a39` | `sbb $0x0,%r9` | Top difference minus exactly the borrow-in |
| `0x2760a3d` | `setb %cl` | Overall borrow-out captured |
| `0x2760a40` | `xor %eax,%eax` | Default flag 0 |
| `0x2760a42` | `mov %r9,0x18(%rdx)` | Top-word result stored, before any borrow check |
| `0x2760a46` | `cmp %rsi,%r8` | Top words compared |
| `0x2760a49` | `jb 0x2760a63` | Top minuend below top subtrahend: failure store |
| `0x2760a4b` | `test %cl,%cl` | Borrow-out tested |
| `0x2760a4d` | `jne 0x2760a63` | Borrow-out set: failure store |
| `0x2760a4f` | `movups (%rdx),%xmm0` | Success: result low half loaded |
| `0x2760a52` | `movups 0x10(%rdx),%xmm1` | Success: result high half loaded |
| `0x2760a56` | `movups %xmm1,0x18(%rdi)` | Success: result high half stored at out+24 |
| `0x2760a5a` | `movups %xmm0,0x8(%rdi)` | Success: result low half stored at out+8 |
| `0x2760a5e` | `mov $0x1,%eax` | Success flag |
| `0x2760a63` | `mov %rax,(%rdi)` | Flag stored at out |
| `0x2760a66` | `ret` | Return; no value in rax beyond the flag store |

In words, with all values little-endian and unsigned: flag = 1 if minuend >= subtrahend as 256-bit integers, else 0. On success, out+8 holds the 32-byte difference. On failure, out+8 is untouched. Both failure branches land on the same flag store at `0x2760a63`; the `jb` condition (top minuend below top subtrahend) already implies borrow-out, so the `cl` test alone would reach the same store — the duplication is observed, its reason is not claimed.

### The minuend is rewritten regardless of success

This is the packet's sharpest edge and must not be softened: words 0–2 of the minuend are rewritten by the `sub`/`sbb` chain, and word 3 is stored at `0x2760a42` **before** either borrow check. A caller that reads the minuend after a failed call therefore sees the raw wrapped difference, not the original value. Only two things are success-gated: the copy to out+8 and the flag value 1. The checker and tests lock this with the zero-minus-one edge (flag 0, out untouched, minuend rewritten to all `0xff`) and the covered-borrow edge (low words borrow, top word covers it, flag 1).

### Incoming calls and data edges

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` call sites, all inside the caller FDE `[0x2760040, 0x2760a04)`: `0x2760924`, `0x276095c`, `0x2760998`. Each was confirmed as an instruction start by linear disassembly from that FDE start, and the retained `caller.objdump.txt` shows all three. The scan is explicitly not a complete xref census: indirect calls and data-pointer references are not covered by it.
- No relocation record of any type in `.rela.dyn` names this window as addend, and a full `readelf -r` grep for `0x2760a10` also finds zero hits. The window is reached by direct calls only, as far as the retained evidence shows.
- No RIP-relative operand, table, or constant pool appears anywhere in the window: the only immediates are the borrow trick's `0xff`, the success flag `1`, and the branch displacements, all locked at fixed offsets.

## Inferences

- The label "checked 256-bit subtract" is an inference from the observed rule: four 64-bit words, a borrow chain, and a success flag that is exactly the no-borrow condition. It is kept separate from the observed bytes.
- The three call sites sharing one caller FDE suggests one caller routine uses this helper three times, but the caller's identity, purpose, and argument setup are not analyzed here and no claim is made about them.
- The `jb`/`jne` duplication may reflect compiler output shape, but no compiler or source-level claim is made.

## Unknowns

- What the 256-bit values represent (amounts, hashes, keys, counters, or something else) is unknown and not claimed.
- Whether the caller relies on, ignores, or is surprised by the unconditional minuend rewrite is unknown; the packet reports the rewrite, not a bug.
- Whether other callers reach this window indirectly is unknown; the scan covers direct `e8` sites only.

## Limits

- No stdlib type, source-level function, value meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation absence covers `.rela.dyn` records only as locked by the checker (the full-section grep is reported separately above).
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
