# foundation-tiny-two-byte-gate-94: what does the 20-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 20-byte FDE window, its 12 int3 padding bytes, the two-byte gate rule, the two naming slots, and the zero-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the two naming slots, the tables that hold them, any return-value contract beyond the observed low byte, other two-byte gates, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a two-byte gate that returns 0 when the first byte is zero, and otherwise returns exactly whether the second byte is zero. Its distinctive property is the minimal shape itself — a zero-extended first byte gating a single equality test, with no store, no call, and no branch beyond the two forward jumps. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51647b0`, no open pull request title mentions it or tiny-two-byte-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

Weakness stated head-on: this is a tiny gate — 20 bytes, two bytes read, no store, no caller found. It is bound because the rule is exact and fully locked (every instruction at a fixed offset, both naming slots, the zero-caller scan), not because it is rich.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tiny_two_byte_gate.py --check research/work-items/foundation-tiny-two-byte-gate-94/evidence.json
python3 -m unittest tests.test_foundation_tiny_two_byte_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51647b0 --stop-address=0x51647d0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x29b594` and the next FDE at `0x29b5a8`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29b594` describes `[0x51647b0, 0x51647c4)`, 20 bytes (CIE at offset 0, `zR` pcrel sdata4: field VA `0xf7cab4` + `0x41e7cfc` = `0x51647b0`, range `0x14`). GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x51647c3` ends at `0x51647c4`).
- The padding is exactly 12 bytes of `int3` (`0xcc`), from `0x51647c4` to `0x51647d0`: the next FDE starts at `0x51647d0` (`[0x51647d0, 0x51647da)`, 0x0a bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 32-byte stride (20 + 12) is not the FDE extent, and any description of this window with a 32-byte body would overstate the frame.
- The window opens with `endbr64`.

### Body behavior: tiny two-byte gate

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
|----|-------------|------|
| `0x51647b0` | `endbr64` | Entry landing pad |
| `0x51647b4` | `movzbl 0x58(%rdi),%eax` | Load first byte, zero-extended |
| `0x51647b8` | `test %al,%al` | First byte zero test |
| `0x51647ba` | `je 0x51647c3` | Zero first byte → return 0 |
| `0x51647bc` | `cmpb $0x0,0x68(%rdi)` | Second byte zero test |
| `0x51647c0` | `sete %al` | 1 iff second byte is zero |
| `0x51647c3` | `ret` | Return |

Rule, stated exactly:

- byte `[rdi+0x58] == 0` → return 0. The second byte is never read on this path.
- Else → return 1 iff byte `[rdi+0x68] == 0`, else 0.

Note the order the bytes force: the first byte gates everything, and the second byte is tested only when the first byte is nonzero. The `movzbl` zero-extends the first byte into `eax`, so on the zero-first path `eax` is already 0 at the shared `ret`; on the second-byte path `sete` writes only the low byte, but the high bytes of `eax` were already cleared by the `movzbl`, so the `sete` low byte is the whole return value — there is no stale-high-byte caveat.

### Incoming calls: zero direct callers

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites targeting this window — explicitly not a complete xref census: indirect reachability (including through whatever tables hold the two naming slots below) is neither claimed nor excluded.

### Data edge: two naming slots, reported as a list

Exactly two relocation records of any type in any `.rela.*` section name this window as addend, both `R_X86_64_RELATIVE` in `.rela.dyn`: slots `0x575b240` and `0x57783d0`. The checker locks exactly this two-slot list (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked). This is reported as a slot list, not a single naming slot, and nothing about the tables that hold these slots — their layout, purpose, or relationship to this window — is claimed.

### Scout precision

No scout correction needed: every scouted element verified exactly (FDE range, 20-byte body, 12 padding bytes, both rule paths including the `endbr64` open, zero direct callers, the two naming slots, nearest claimed window). Nearest claimed window: field-walk shift store `0x514ab20` (packet #39), `0x19c90` away.

### Symbol hint, explicitly disclaimed

Objdump annotates the address with a nearest `ctype` `do_widen` symbol `0x1bc9b0` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences

- The "tiny two-byte gate" label is an inference from the observed rule shape (a first-byte gate selecting a second-byte equality test). It is kept separate from the observed rule above.
- The two naming slots look like entries of pointer tables, but the tables' identities and the window's role in them are not claimed.

## Unknowns

- What the struct fields at +0x58/+0x68 mean, and what larger structure they belong to.
- What the two-slot tables are, and how this window is reached at runtime (no direct caller was found).
- Whether any consumer distinguishes the window's 0 return on the first-byte path from its 0 return on the second-byte-nonzero path.

## Limits

- No stdlib type, source-level function, field meaning, table identity, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
