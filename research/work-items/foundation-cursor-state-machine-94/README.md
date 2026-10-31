# foundation-cursor-state-machine-94: what does the 82-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 82-byte FDE window, its 14 int3 padding bytes, the cursor/state-machine rule, the fifteen naming slots, and the zero-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the marker bytes 0x67/0x50, the meaning of the fifteen naming slots, the pointer table that holds them, any return value, other cursor/state helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a single-step state machine that either stamps one of two marker bytes or advances a cursor by a length-prefixed step. Its distinctive property is the step shape itself — a flag byte selects the first marker, an unsigned counter gate selects the second, and only when both gates pass does the counter drop by 2 while the cursor jumps by a sign-extended, byte-swapped 16-bit length plus 2. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x47d6b90`, no open pull request title mentions it or cursor-state-machine, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

Distinction from packet #46, stated explicitly: packet #46's cursor walk loop (`0x3c1d690`) walks 0x38-step nodes until a limit is reached exactly — a loop to a limit. This window is a single-step advance driven by one 16-bit length prefix, with no loop and no limit check; the two windows are not merged, and no shared primitive is claimed between them.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_cursor_state_machine.py --check research/work-items/foundation-cursor-state-machine-94/evidence.json
python3 -m unittest tests.test_foundation_cursor_state_machine -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x47d6b90 --stop-address=0x47d6bf0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x21c9d0` and the next FDE at `0x21c9e4`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x21c9d0` describes `[0x47d6b90, 0x47d6be2)`, 82 bytes (CIE at offset 0, `zR` pcrel sdata4: field VA `0xefdef0` + `0x38d8ca0` = `0x47d6b90`, range `0x52`). GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x47d6be1` ends at `0x47d6be2`).
- The padding is exactly 14 bytes of `int3` (`0xcc`), from `0x47d6be2` to `0x47d6bf0`: the next FDE starts at `0x47d6bf0` (`[0x47d6bf0, 0x47d6bfa)`, 0x0a bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 96-byte stride (82 + 14) is not the FDE extent, and any description of this window with a 96-byte body would overstate the frame.
- The window opens directly with the flag-byte comparison — no `endbr64` (an observation, not a scout deviation; the scout did not claim one).

### Body behavior: cursor/state machine

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
|----|-------------|------|
| `0x47d6b90` | `cmpb $0x0,0x1f0(%rdi)` | Flag byte must be nonzero to continue |
| `0x47d6b97` | `je 0x47d6bd2` | Zero flag byte → marker path |
| `0x47d6b99` | `mov 0x1e0(%rdi),%rax` | Load counter |
| `0x47d6ba0` | `cmp $0x1,%rax` | Counter gate |
| `0x47d6ba4` | `jbe 0x47d6bda` | Counter ≤ 1 (unsigned) → marker path |
| `0x47d6ba6` | `add $0xfffffffffffffffe,%rax` | Counter − 2 |
| `0x47d6baa` | `mov %rax,0x1e0(%rdi)` | Store counter back |
| `0x47d6bb1` | `mov 0x1d0(%rdi),%rax` | Load cursor |
| `0x47d6bb8` | `movzwl (%rax),%ecx` | Load u16 length at cursor, zero-extended |
| `0x47d6bbb` | `rol $0x8,%cx` | Byte-swap the 16-bit length |
| `0x47d6bbf` | `movswq %cx,%rcx` | Sign-extend the swapped length |
| `0x47d6bc3` | `add %rcx,%rax` | Cursor += signed length |
| `0x47d6bc6` | `add $0x2,%rax` | Cursor += 2 (past the length prefix itself) |
| `0x47d6bca` | `mov %rax,0x1d0(%rdi)` | Store cursor back |
| `0x47d6bd1` | `ret` | Return from the advance path |
| `0x47d6bd2` | `movb $0x67,0x1f3(%rdi)` | Zero-flag marker |
| `0x47d6bd9` | `ret` | Return from the flag path |
| `0x47d6bda` | `movb $0x50,0x1f3(%rdi)` | Counter-gate marker |
| `0x47d6be1` | `ret` | Return from the counter path |

Rule, stated exactly:

- byte `[rdi+0x1f0] == 0` → store `0x67` at `[rdi+0x1f3]`, return. The counter is untouched and the cursor does not move.
- Else qword `[rdi+0x1e0] <= 1` (unsigned `jbe`) → store `0x50` at `[rdi+0x1f3]`, return. The counter is untouched and the cursor does not move.
- Else → qword `[rdi+0x1e0] -= 2`; cursor `[rdi+0x1d0] += sign_extend(byte_swap(u16 at old cursor)) + 2`; return. No marker is stored on this path.

Note the order the bytes force: the flag byte gates everything, the counter gate is checked only when the flag byte is nonzero, and the advance runs only when both gates pass. The `+2` in the advance is the length prefix's own size: the cursor moves past the 2-byte prefix plus the signed length it names. A negative signed length therefore moves the cursor backwards by up to 32,766 net bytes (length word `0x0080` → swapped `0x8000` → signed −32,768 → delta −32,766); nothing in the window bounds-checks the result.

### Incoming calls: zero direct callers

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites targeting this window — explicitly not a complete xref census: indirect reachability (including through whatever table holds the fifteen naming slots below) is neither claimed nor excluded.

### Data edge: fifteen naming slots, a pointer table

Exactly fifteen relocation records of any type in any `.rela.*` section name this window as addend, all `R_X86_64_RELATIVE` in `.rela.dyn`: slots `0x5721d88`, `0x5722588`, `0x5722d88`, `0x5723588`, `0x5723d88`, `0x5724588`, `0x5724d88`, `0x5725588`, `0x5725d88`, `0x5726588`, `0x5726d88`, `0x5727588`, `0x5727d88`, `0x5728588`, `0x5728d88` — spaced exactly `0x800` apart. The checker locks exactly this fifteen-slot list (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked). This is reported as a slot list forming a pointer table, not a single naming slot, and nothing about the table that holds these slots — its layout, purpose, or relationship to this window — is claimed.

### Scout precision

No scout correction needed: every scouted element verified exactly (FDE range, 82-byte body, 14 padding bytes, all three rule paths including the marker bytes and the length-prefix advance, zero direct callers, the fifteen naming slots and their 0x800 spacing, nearest claimed window). Nearest claimed window: three-field tail gate `0x473b120` (packet #48), `0x9ba70` away.

### Symbol hint, explicitly disclaimed

Objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0x7d1270` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences

- The "cursor/state machine" label is an inference from the observed rule shape (marker stores on two gated paths, a length-driven single-step advance on the third). It is kept separate from the observed rule above.
- The two marker bytes (0x67, 0x50) look like state tags, but no meaning is assigned to either value.
- The fifteen regularly spaced naming slots look like entries of one pointer table, but the table's identity and the window's role in it are not claimed.

## Unknowns

- What the struct fields at +0x1d0/+0x1e0/+0x1f0/+0x1f3 mean, and what larger structure they belong to.
- What the marker bytes signify to any consumer, and whether any consumer reads them.
- What the fifteen-slot table is, and how this window is reached at runtime (no direct caller was found).
- What value, if any, the window returns: `rax` at each `ret` is the counter, the old cursor plus step, or an untouched caller value depending on the path, and no return contract is claimed.
- Whether the advance path's unbounded signed step is ever exercised with a negative length in practice.

## Limits

- No stdlib type, source-level function, field meaning, marker meaning, table identity, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
