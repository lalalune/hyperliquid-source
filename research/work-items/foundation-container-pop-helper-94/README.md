# foundation-container-pop-helper-94: what does the container pop helper window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 87-byte FDE window with nine padding bytes, the container pop rule it implements, the exact incoming-call scan result (one direct site in one caller FDE), and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the caller, the purpose of the 0x200 tag math, and any wider container family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a two-path container pop helper — equality of two struct pointers selects a pop path with distinctive 0x200 tag math, otherwise a step-back path with the same counter decrement. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5178be0`, no open pull request title mentions it or container-pop-helper, and its bytes overlap nothing in packets #1–#78.

## Scout note

The round-12 scout note listed this window (ranked #2) with FDE `[0x5178be0, 0x5178c37)`, 87 bytes, 9 padding bytes, one direct caller boundary-confirmed, no naming relocation, and the pop path's distinctive 0x200 tag math. Every element verified exactly. No numeric correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode at any instruction start inside it), while the one direct site is an incoming call from one caller FDE — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_container_pop_helper.py --check research/work-items/foundation-container-pop-helper-94/evidence.json
python3 -m unittest tests.test_foundation_container_pop_helper -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5178be0 --stop-address=0x5178c40 artifacts/node/94/hl-node
objdump -d --start-address=0x508f300 --stop-address=0x508f7ed artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its nine padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE, from which the call site was confirmed as an instruction start. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c8c0` (this window), `0x29c8d4` (the next FDE), `0x62c7dc` (the caller FDE), plus the shared CIEs at offsets `0` and `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c8c0` describes `[0x5178be0, 0x5178c37)`, 87 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Nine `int3` bytes (`0xcc`) follow at `0x5178c37`–`0x5178c3f`, and the next FDE starts exactly at `0x5178c40` (record at `.eh_frame+0x29c8d4`, range to `0x5178e43`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x1d0de0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: container pop helper, no calls, one forward branch

Inputs: `rdi` = struct pointer. Fields read: qwords at `[rdi+0x8]` and `[rdi+0x10]` (compared), `[rdi+0x20]` and `[rdi+0x20]-8` (pop path only), counter qword at `[rdi+0x28]` (both paths). Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5178be0` | `endbr64` | Landing pad |
| `0x5178be4` | `mov 0x8(%rdi),%rax` | First pointer loaded |
| `0x5178be8` | `cmp 0x10(%rdi),%rax` | Computes `[rdi+0x10] - [rdi+0x8]` |
| `0x5178bec` | `je 0x5178c00` | Equal → pop path |
| `0x5178bee` | `sub $0x20,%rax` | Else path: step first pointer back |
| `0x5178bf2` | `subq $0x10,0x28(%rdi)` | Else path: counter decrement |
| `0x5178bf7` | `mov %rax,0x8(%rdi)` | Else path: pointer store |
| `0x5178bfb` | `ret` | Else path return (rax = new `[rdi+0x8]`) |
| `0x5178bfc` | `nopl 0x0(%rax)` | Alignment padding, targeted by no branch |
| `0x5178c00` | `mov 0x20(%rdi),%rax` | Pop path: stack top loaded |
| `0x5178c04` | `lea -0x8(%rax),%rdx` | Popped-slot address |
| `0x5178c08` | `mov %rdx,0x20(%rdi)` | Stack top moved down by 8 |
| `0x5178c0c` | `mov -0x8(%rax),%rdx` | Popped value loaded |
| `0x5178c10` | `subq $0x10,0x28(%rdi)` | Pop path: counter decrement |
| `0x5178c15` | `lea 0x200(%rdx),%rax` | Tag add (distinctive, unexplained) |
| `0x5178c1c` | `movq %rdx,%xmm0` | Value to xmm0 low half |
| `0x5178c21` | `movq %rax,%xmm1` | Tagged value to xmm1 low half |
| `0x5178c26` | `sub $0x20,%rax` | Tag adjust: tagged − 0x20 |
| `0x5178c2a` | `punpcklqdq %xmm1,%xmm0` | Pair pack: (value, tagged) |
| `0x5178c2e` | `mov %rax,0x8(%rdi)` | Pop path: pointer store (value + 0x1e0) |
| `0x5178c32` | `movups %xmm0,0x10(%rdi)` | Pair store: `[rdi+0x10]` = value, `[rdi+0x18]` = value + 0x200 |
| `0x5178c36` | `ret` | Pop path return (rax = value + 0x1e0) |

Rule: let `a = [rdi+0x8]`, `b = [rdi+0x10]`, `top = [rdi+0x20]`, `val = [top-8]`. If `a == b` (pop path): `[rdi+0x20] = top - 8`, `[rdi+0x28] -= 0x10`, `[rdi+0x8] = val + 0x1e0`, `[rdi+0x10] = val`, `[rdi+0x18] = val + 0x200`, and rax returns `val + 0x1e0`. Otherwise (else path): `[rdi+0x8] = a - 0x20`, `[rdi+0x28] -= 0x10`, `[rdi+0x10]` and `[rdi+0x20]` untouched, and rax returns `a - 0x20`. All arithmetic wraps at 64 bits. The 0x200 tag math is locked exactly and not explained: the stored `[rdi+0x8]` pointer is `val + 0x1e0` (tagged minus 0x20) while the stored `[rdi+0x18]` slot is `val + 0x200`.

Worked edges: pop path with `a = b = 100`, `top = 1000`, `val = 7` → `[rdi+0x8] = 0x1e7`, `[rdi+0x10] = 7`, `[rdi+0x18] = 0x207`, `[rdi+0x20] = 992`; else path with `a = 100`, `b = 50` → `[rdi+0x8] = 68` (100 − 0x20), `[rdi+0x10]`/`[rdi+0x20]` untouched; pop path with `val = 0` → `[rdi+0x8] = 0x1e0`, `[rdi+0x10] = 0`, `[rdi+0x18] = 0x200`; else path with `a = 0x20` → `[rdi+0x8] = 0`; pop path with `val = 2^64 - 1` wraps to `[rdi+0x8] = 0x1df`, `[rdi+0x18] = 0x1ff`.

The 4-byte `nopl` at `0x5178bfc` sits between the else-path `ret` and the pop path and is targeted by no branch (the `je` lands at `0x5178c00`); it is locked as bytes, not behavior. The `0xe8` byte inside `sub $0x20,%rax` is an operand byte of that instruction, not a call opcode — the checker locks every instruction start, and none of them is a call.

### Incoming calls: one direct site, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site whose rel32 lands on the window start — explicitly not a complete xref census (indirect calls, tail jumps, and PLT references are out of scope):

| Call site | Caller FDE | Setup immediately before the call |
| --- | --- | --- |
| `0x508f33e` | `0x508f300..0x508f7ed` | `lea 0x228(%rdi),%rdi` |

The site was confirmed as an instruction start by linear disassembly from its caller FDE start. The caller setup computes the struct pointer as `rdi + 0x228`; that offset is locked as bytes, and no caller purpose is claimed from it.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

### Nearest claimed window

The nearest claimed window is the tiny two-byte gate `0x51647b0` (packet #72), `0x14430` away — outside the scout's `0x2000` exclusion radius around claimed windows.

## Inferences (kept separate from observations)

- The "container pop helper" label is an inference from the observed rule, not a source-level name.
- The fields are called "first pointer", "second pointer", "stack top", and "counter" only by their roles in the branches; their struct meaning is unknown.
- The 0x200 tag math is distinctive but unexplained; no container type, tag scheme, or element size is claimed from it.
- Both paths returning the new `[rdi+0x8]` value in rax is observed from the retained bytes; whether any caller uses that return value is unknown.

## Unknowns

- What the struct is, what the fields mean, and what the caller does with the result.
- Why the pop path tags the popped value by 0x200 while storing `val + 0x1e0` as the pointer.
- Whether any indirect caller or PLT reference reaches this window (outside the scan's scope).
- The source-level function, type, or component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
