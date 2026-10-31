# foundation-multi-path-tail-dispatcher-94: what does the 85-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 85-byte FDE window, its 11 int3 padding bytes, the multi-path dispatch rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the tag values, the tail targets' behavior, the caller's behavior beyond the call itself, other tag-gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a two-level tag dispatch with three distinct tail targets and three distinct pointer adjustments, plus a plain return path. Its distinctive property is that the first tag byte selects between an immediate tail jump and a second dispatch, and the second dispatch itself has two confirmed tail paths gated on two separate confirmation bytes. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4341b60`, no open pull request title mentions it or multi-path-tail-dispatcher, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

Family caution, addressed head-on: this window is in the same broad tag-dispatched-tail-gate class as packet #62's two-path tail gate (0x1fc7780) and packet #66's quirky tag gate (0x223e3a0). It is bound on its own merits, not as a family member or sibling of either: it has three tail targets (not one or two), a two-level dispatch (the first tag byte gates a second tag byte), and three distinct pointer adjustments (0xdc0, 0xb8, 0xc8). No census of the class is claimed, and no shared-primitive decode is attempted.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_multi_path_tail_dispatcher.py --check research/work-items/foundation-multi-path-tail-dispatcher-94/evidence.json
python3 -m unittest tests.test_foundation_multi_path_tail_dispatcher -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4341b60 --stop-address=0x4341bc0 artifacts/node/94/hl-node
objdump -d --start-address=0x439baf0 --stop-address=0x439ec8d artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `caller.objdump.txt` file retains complete disassembly of the confirmed caller FDE. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x1e3d7c`, the next FDE at `0x54f618`, the caller FDE at `0x556f98`, and the three tail-target FDEs at `0x54f690`, `0x550138`, and `0x56bbac`. The checker locks these raw FDE records and their shared CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1e3d7c` describes `[0x4341b60, 0x4341bb5)`, 85 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x4341bb0` ends at `0x4341bb5`).
- The padding is exactly 11 bytes of `int3` (`0xcc`), from `0x4341bb5` to `0x4341bc0`: the next FDE starts at `0x4341bc0` (`[0x4341bc0, 0x4341ea1)`, 0x2e1 bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 96-byte stride (85 + 11) is not the FDE extent, and any description of this window with a 96-byte body would overstate the frame.
- The window opens directly with the tag load — no `endbr64` (an observation, not a scout deviation).

### Body behavior: two-level dispatch, three tail targets, one return

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| 0x4341b60 | `movzbl 0x29d0(%rdi),%eax` | t = byte at +0x29d0 |
| 0x4341b67 | `test %eax,%eax` | t == 0? |
| 0x4341b69 | `je 0x4341b7c` | zero-tag path: second dispatch |
| 0x4341b6b | `cmp $0x3,%eax` | t == 3? |
| 0x4341b6e | `jne 0x4341ba8` | other tags return |
| 0x4341b70 | `add $0xdc0,%rdi` | three-tag path: advance the pointer |
| 0x4341b77 | `jmp 0x4341ef0` | three-tag path: tail-jump |
| 0x4341b7c | `movzbl 0x55(%rdi),%eax` | u = byte at +0x55 |
| 0x4341b80 | `cmp $0x4,%eax` | u == 4? |
| 0x4341b83 | `je 0x4341ba9` | four path |
| 0x4341b85 | `cmp $0x3,%eax` | u == 3? |
| 0x4341b88 | `jne 0x4341ba8` | other second tags return |
| 0x4341b8a | `cmpb $0x3,0xdb0(%rdi)` | first confirmation byte at +0xdb0 |
| 0x4341b91 | `jne 0x4341ba8` | unconfirmed: return |
| 0x4341b93 | `cmpb $0x3,0xda8(%rdi)` | second confirmation byte at +0xda8 |
| 0x4341b9a | `jne 0x4341ba8` | unconfirmed: return |
| 0x4341b9c | `add $0xc8,%rdi` | confirmed three path: advance the pointer |
| 0x4341ba3 | `jmp 0x43439c0` | confirmed three path: tail-jump |
| 0x4341ba8 | `ret` | return for other tags, other second tags, and unconfirmed paths |
| 0x4341ba9 | `add $0xb8,%rdi` | four path: advance the pointer |
| 0x4341bb0 | `jmp 0x44c6e70` | four path: tail-jump |

Rule, stated exactly:

- t = byte [rdi+0x29d0].
- t == 3 → rdi += 0xdc0, tail-jump to 0x4341ef0 (the second dispatch is not consulted).
- t == 0 → u = byte [rdi+0x55]; u == 4 → rdi += 0xb8, tail-jump to 0x44c6e70; u == 3 and byte [rdi+0xdb0] == 3 and byte [rdi+0xda8] == 3 → rdi += 0xc8, tail-jump to 0x43439c0; otherwise → return, with no store and no pointer change.
- Otherwise (any other t) → return, with no store and no pointer change.

The tail targets are named, not decoded: all three are FDE starts (`[0x4341ef0, 0x4341fd3)`, `[0x43439c0, 0x4343a5c)`, `[0x44c6e70, 0x44c6f5c)`), and no claim is made about what they do with the adjusted argument. The window contains no calls, no stores, and no return value on the jump paths — it either returns (fall-through paths) or transfers control.

### Incoming calls: exactly one direct site

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site targeting this window:

- `0x439ec38` (bytes `e8 23 2f fa ff`), confirmed as an instruction start by linear disassembly from its caller FDE start (`[0x439baf0, 0x439ec8d)`). The caller sets `rdi` from `mov 0x50(%rsp),%rdi` immediately before the call; caller purpose beyond that is not claimed.

This is explicitly not a complete xref census: indirect callers, if any, are neither claimed nor excluded.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked by the checker). The absence of a naming relocation does not identify the window's provenance.

### Symbol hint, explicitly disclaimed

Objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0xc662a0` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

### Nearest claimed window

Three-field tail gate `0x473b120` (packet #48), `0x3f95c0` away; nothing in `0x4341bxx` is claimed by any other packet.

### Scout agreement

Every scouted element verified exactly: FDE range, 85-byte body, 11 padding bytes, all three tail paths and targets, the one caller and its FDE range, no naming relocation, and the nearest claimed window. No scout correction was needed.

## Inferences

- The "multi-path tail dispatcher" label is an inference from the observed rule shape (a two-level tag dispatch gating three tail jumps to three targets); it is not a source-level name.
- The tag values 3, 0, 4, the confirmation value 3, and the offsets 0x29d0, 0x55, 0xdb0, 0xda8, 0xdc0, 0xb8, and 0xc8 are observed constants; what they mean for the caller's data is unknown.

## Unknowns

- What the three tail targets do with the pointer, and why each path advances it by a different amount.
- What the struct at `rdi` is, and what the bytes at +0x29d0, +0x55, +0xdb0, and +0xda8 represent.
- Whether any indirect caller reaches this window.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
