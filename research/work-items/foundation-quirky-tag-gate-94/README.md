# foundation-quirky-tag-gate-94: what does the 33-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 33-byte FDE window, its 15 int3 padding bytes, the quirky tag-gate rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the tag values, the tail target's behavior, the caller's behavior beyond the call itself, other tag-gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: eleven instructions, no calls inside, two tag tests, and a rule fully determined by one tag byte and one confirmation byte. Its distinctive property is the shared tail target reached two ways: with `rdi + 0x18` on the zero-tag path and with `rdi` unchanged on the confirmed three-tag path. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x223e3a0`, no open pull request title mentions it or quirky-tag-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_quirky_tag_gate.py --check research/work-items/foundation-quirky-tag-gate-94/evidence.json
python3 -m unittest tests.test_foundation_quirky_tag_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x223e3a0 --stop-address=0x223e3d0 artifacts/node/94/hl-node
objdump -d --start-address=0x22b1080 --stop-address=0x22b47bf artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `caller.objdump.txt` file retains complete disassembly of the confirmed caller FDE. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x59248`, the next FDE at `0x5925c`, the caller FDE at `0x3bbf98`, and the tail-target FDE at `0x3b2f0c`. The checker locks these raw FDE records and their shared CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x59248` describes `[0x223e3a0, 0x223e3c1)`, 33 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x223e3bc` ends at `0x223e3c1`).
- The padding is exactly 15 bytes of `int3` (`0xcc`), from `0x223e3c1` to `0x223e3d0`: the next FDE starts at `0x223e3d0` (`[0x223e3d0, 0x223e400)`, 0x30 bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 48-byte stride (33 + 15) is not the FDE extent, and any description of this window with a 48-byte body would overstate the frame.
- The window opens directly with the tag load — no `endbr64` (an observation, not a scout deviation).

### Body behavior: one tag byte, one confirmation byte, two ways to the same tail

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| 0x223e3a0 | `movzbl 0x30(%rdi),%eax` | t = byte at +0x30 |
| 0x223e3a4 | `test %eax,%eax` | t == 0? |
| 0x223e3a6 | `je 0x223e3b8` | zero-tag path |
| 0x223e3a8 | `cmp $0x3,%eax` | t == 3? |
| 0x223e3ab | `jne 0x223e3b7` | other tags return |
| 0x223e3ad | `cmpb $0x2,0x10(%rdi)` | confirmation byte at +0x10 |
| 0x223e3b1 | `jne 0x22429e0` | confirmed three-tag path: tail-jump, rdi unchanged |
| 0x223e3b7 | `ret` | return for other tags, and for t == 3 with confirmation byte == 2 |
| 0x223e3b8 | `add $0x18,%rdi` | zero-tag path: advance the pointer |
| 0x223e3bc | `jmp 0x22429e0` | zero-tag path: tail-jump with rdi + 0x18 |

Rule, stated exactly:

- t = byte [rdi+0x30].
- t == 0 → rdi += 0x18, tail-jump to 0x22429e0.
- t == 3 and byte [rdi+0x10] != 2 → tail-jump to 0x22429e0 with rdi unchanged.
- Otherwise (any other t, or t == 3 with byte [rdi+0x10] == 2) → return, with no store and no pointer change.

The shared tail target with and without the add is the window's distinctive (odd) property; it is stated exactly here and is not smoothed over into a single path. The tail target is named, not decoded: it is an FDE start (`[0x22429e0, 0x2242adc)`), and no claim is made about what it does with the adjusted (or unadjusted) argument. The window contains no calls, no stores, and no return value on the jump paths — it either returns (fall-through paths) or transfers control.

### Incoming calls: exactly one direct site

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site targeting this window:

- `0x22b45c9` (bytes `e8 d2 9d f8 ff`), confirmed as an instruction start by linear disassembly from its caller FDE start (`[0x22b1080, 0x22b47bf)`). The caller sets `rdi` from `r15` (`mov %r15,%rdi`) immediately before the call; caller purpose beyond that is not claimed.

This is explicitly not a complete xref census: indirect callers, if any, are neither claimed nor excluded.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked by the checker). The absence of a naming relocation does not identify the window's provenance.

### Symbol hint, explicitly disclaimed

Objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol more than `0x2d69a60` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

### Nearest claimed window

Tagged 40-byte copy `0x22155a0` (packet #22), `0x28e00` away; nothing in `0x223e3xx` is claimed by any other packet.

### Scout agreement

Every scouted element verified exactly: FDE range, 33-byte body, 15 padding bytes, both tail paths and the shared target, the one caller and its FDE range, no naming relocation, and the nearest claimed window. No scout correction was needed.

## Inferences

- The "quirky tag gate" label is an inference from the observed rule shape (a tag byte plus a confirmation byte gating two tail jumps to one target); it is not a source-level name.
- The tag values 0 and 3, the confirmation value 2, and the offsets 0x30, 0x10, and 0x18 are observed constants; what they mean for the caller's data is unknown.

## Unknowns

- What the tail target at 0x22429e0 does with the pointer, and why the zero-tag path advances it by 0x18 while the confirmed three-tag path does not.
- What the struct at `rdi` is, and what the bytes at +0x30 and +0x10 represent.
- Whether any indirect caller reaches this window.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
