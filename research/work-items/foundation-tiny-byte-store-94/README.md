# foundation-tiny-byte-store-94: what does the 25-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 25-byte FDE window, its seven int3 padding bytes, the exact two-value store rule, the ten RELATIVE pointer-table slots naming it, and the zero-direct-caller scan.
- Excluded: the meaning of the stored values 0x5a/0x57, the meaning of the field offsets 0x1f2/0x1f3, the purpose of the pointer table, the caller's behavior (there is no direct caller), other byte-store or flag helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: seven instructions, no calls, no branches, and a rule fully determined by one compare and one constant add. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x24f13b0`, no open pull request title mentions it or tiny-byte-store, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tiny_byte_store.py --check research/work-items/foundation-tiny-byte-store-94/evidence.json
python3 -m unittest tests.test_foundation_tiny_byte_store -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x24f13b0 --stop-address=0x24f13d0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. There is no caller file: the incoming scan finds zero direct calls, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x82f38`, and the next FDE at `0x3e2070`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x82f38` describes `[0x24f13b0, 0x24f13c9)`, 25 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x24f13c8` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x24f13d0`, only because seven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those seven padding bytes, and the checker locks the 25-byte body and the padding separately.
- The next FDE starts exactly at `0x24f13d0` (`[0x24f13d0, 0x24f1798)`, 0x3c8 bytes); the checker locks its record length field, and its full record is retained in `frames.txt`.

### Body behavior: one compare, one constant add, no calls, no branches

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x24f13b0` | `xor %eax,%eax` | Clear the result register |
| `0x24f13b2` | `cmpb $0x0,0x1f2(%rdi)` | Input byte == 0 test |
| `0x24f13b9` | `sete %al` | Flag = 1 iff input byte is 0 |
| `0x24f13bc` | `lea (%rax,%rax,2),%eax` | eax = flag * 3 |
| `0x24f13bf` | `add $0x57,%eax` | eax = flag * 3 + 0x57 |
| `0x24f13c2` | `mov %al,0x1f3(%rdi)` | Store the low byte |
| `0x24f13c8` | `ret` | |

The rule is therefore `[rdi+0x1f3] = (byte [rdi+0x1f2] == 0 ? 0x5a : 0x57)`, and the same value is returned in `eax`. There is no low-byte caveat on the return value: `eax` is fully cleared before the flag is set, so the returned register holds exactly 0x5a or 0x57, not just a low byte. The window opens directly with the xor — no `endbr64` (an observation, not a scout deviation).

### Data edge: ten RELATIVE slots, a pointer table, not a naming relocation

The full `.rela.*` scan (80,022 `.rela.dyn` + 278 `.rela.plt` entries) finds exactly ten records naming this window as addend, all of type `R_X86_64_RELATIVE`, all in `.data.rel.ro` (VA range `[0x56632a0, 0x576d770)`):

`0x56a8f30`, `0x56a9730`, `0x56aa730`, `0x56aaf30`, `0x56abf30`, `0x56af730`, `0x56b3f30`, `0x56b4f30`, `0x56b5730`, `0x56b6730`.

Ten slots with the same addend, each at offset `0x30` within its table entry, are a pointer table — one function pointer per entry — not a single naming relocation. No single slot is claimed as "the" name for this window, and nothing about the table's purpose, owner, or entries is claimed. The checker locks exactly these ten slots: any added, removed, or retyped slot fails the check.

### Call edge: zero direct callers

The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to this window. Register-indirect references, other pointer paths (including the ten table slots above, which are data, not calls), prefixes, and data sections are not a complete xref census, so indirect reachability through the table is neither claimed nor excluded.

### Symbol hint, explicitly disclaimed

GNU objdump annotates the window's address with the nearest preceding symbol, a `ctype` `do_widen` label more than 0x2ab6a50 bytes below. A nearest-symbol annotation at that distance proves nothing about provenance: no stdlib or private origin is claimed either way, and the label is not used as evidence anywhere in this packet.

### Scout notes

No scout correction was needed: every scouted element verified exactly (FDE range, 25-byte body, seven padding bytes, the two stored values, zero direct callers, ten RELATIVE slots). The scout's shorthand spacing description for the slots ("0x800/0x1000 apart") is not repeated here because the actual gaps vary (0x800, 0x1000, 0x3800, 0x4800); the exact slot list above replaces it.

### Nearest claimed window

The nearest previously claimed window is the tail-gate at `0x250ab00` (packet #31), `0x19750` away; nothing in `0x24f13xx` is claimed.

## Inferences

- The "tiny byte store" label is an inference from the single-byte read/store shape; it is not a source-level name.
- The two stored values are described as 0x5a/0x57 only because the bytes compute them that way; what they mean to any reader of the field is unknown.
- The ten RELATIVE slots are described as a pointer table only because ten same-addend slots at a repeated entry offset is the shape of one; what the table dispatches to is unknown.

## Unknowns

- The meaning of the stored values 0x5a and 0x57.
- The meaning of the field offsets 0x1f2 and 0x1f3.
- The purpose and owner of the pointer table, and whether any table entry is ever called.
- Whether any caller reaches this window indirectly (the byte-pattern scan is not a complete xref census).
- The source-level function, type, or component this window belongs to beyond the foundation task framing.

## Limits

- No stdlib type, source-level function, field meaning, value meaning, table purpose, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the ten RELATIVE slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
