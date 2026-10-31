# foundation-chained-byte-dword-gate-94: what does the 59-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 59-byte FDE window, its 5 int3 padding bytes, the chained byte/dword gate rule, the two naming slots, and the zero-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the two naming slots, the nearby cluster windows' behavior, other byte/dword gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a chained gate that falls through three byte checks before reaching an unsigned dword comparison. Its distinctive property is the chain shape itself — an early nonzero byte forces 0, a second nonzero byte is returned verbatim, a zero third byte forces 0, and only when all three byte checks pass does the dword comparison decide the result. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5382d50`, no open pull request title mentions it or chained-byte-dword-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

Cluster caution, addressed head-on: two nearby windows (`0x5382c90` and `0x5382d30`, adjacent FDEs in the same field neighborhood at offsets `+0x28a`/`+0x289`/`+0x290`/`+0x98`/`+0x9c`) read the same fields this window reads, and they look like sibling methods of one struct or table. This packet binds ONLY `0x5382d50`; the cluster members are not built here, no census of the cluster is claimed, and building any of them alongside this window is a parent decision, not something this packet assumes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_chained_byte_dword_gate.py --check research/work-items/foundation-chained-byte-dword-gate-94/evidence.json
python3 -m unittest tests.test_foundation_chained_byte_dword_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5382d50 --stop-address=0x5382d90 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x2b2f80` and the next FDE at `0x2b2f94`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b2f80` describes `[0x5382d50, 0x5382d8b)`, 59 bytes (CIE at offset 0, `zR` pcrel sdata4: field VA `0xf944a0` + `0x43ee8b0` = `0x5382d50`, range `0x3b`). GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5382d8a` ends at `0x5382d8b`).
- The padding is exactly 5 bytes of `int3` (`0xcc`), from `0x5382d8b` to `0x5382d90`: the next FDE starts at `0x5382d90` (`[0x5382d90, 0x5382dd2)`, 0x42 bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 64-byte stride (59 + 5) is not the FDE extent, and any description of this window with a 64-byte body would overstate the frame.
- The window opens with `endbr64`.

### Body behavior: chained byte/dword gate

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
|----|-------------|------|
| `0x5382d50` | `endbr64` | Entry marker |
| `0x5382d54` | `xor %eax,%eax` | Clear return value (the zero path) |
| `0x5382d56` | `cmpb $0x0,0x28a(%rdi)` | First byte must be zero |
| `0x5382d5d` | `jne 0x5382d6a` | Nonzero first byte → return 0 |
| `0x5382d5f` | `movzbl 0x290(%rdi),%eax` | Load second byte, zero-extended |
| `0x5382d66` | `test %al,%al` | Second byte must be zero to continue |
| `0x5382d68` | `je 0x5382d70` | Zero second byte → continue |
| `0x5382d6a` | `ret` | Shared return: 0 (first-byte path) or the second byte |
| `0x5382d6b` | `nopl 0x0(%rax,%rax,1)` | 5-byte unreachable alignment padding (follows a ret, targeted by no branch) |
| `0x5382d70` | `movzbl 0x289(%rdi),%eax` | Load third byte, zero-extended |
| `0x5382d77` | `test %al,%al` | Third byte must be nonzero to continue |
| `0x5382d79` | `je 0x5382d6a` | Zero third byte → return 0 |
| `0x5382d7b` | `mov 0x98(%rdi),%eax` | Load dword at +0x98 |
| `0x5382d81` | `cmp %eax,0x9c(%rdi)` | Compare dword at +0x9c against it (AT&T order: computes [0x9c] − [0x98]) |
| `0x5382d87` | `setb %al` | 1 exactly when [0x9c] < [0x98] unsigned (movzbl cleared the upper bits, so the setb low byte is the whole return value) |
| `0x5382d8a` | `ret` | Return the comparison result |

Rule, stated exactly:

- byte `[rdi+0x28a] != 0` → return 0.
- byte `[rdi+0x290] != 0` → return that byte (zero-extended; the second byte is checked before the third, so it takes priority over the third-byte and dword paths).
- byte `[rdi+0x289] == 0` → return 0.
- Otherwise → return 1 exactly when dword `[rdi+0x9c]` is unsigned-less-than dword `[rdi+0x98]`, else 0.

Note the chain order the bytes force: the first byte gates everything, the second byte short-circuits with its own value, and the dword comparison is reached only when the first byte is zero, the second byte is zero, and the third byte is nonzero. The 5-byte `nopl` at `0x5382d6b` sits between the shared return and the third-byte path, follows a `ret`, and is targeted by no branch — it is unreachable alignment padding, locked as body bytes, not an executed instruction.

### Incoming calls: zero direct callers

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites targeting this window — explicitly not a complete xref census: indirect reachability (including through whatever tables hold the two naming slots below) is neither claimed nor excluded.

### Data edge: two naming slots, not one

Exactly two relocation records of any type in any `.rela.*` section name this window as addend, both `R_X86_64_RELATIVE` in `.rela.dyn`: slots `0x57632a8` and `0x5778ae8`. The checker locks exactly this two-slot list (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked). This is reported as a slot list, not a single naming slot, and nothing about the tables that hold these slots — their layout, purpose, or relationship to this window — is claimed.

### Scout precision

No scout correction needed: every scouted element verified exactly (FDE range, 59-byte body, 5 padding bytes, the 5-byte nop between paths, all four rule branches, zero direct callers, the two naming slots, nearest claimed window). Nearest claimed window: two-hop field select `0x5361710` (packet #65), `0x21640` away.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0x3daf50` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences (kept separate from observations)

- The label "chained byte/dword gate" is an inference from the observed rule (three byte checks chained before an unsigned dword comparison). It is not a source-level name.
- The five fields at offsets `+0x28a`, `+0x290`, `+0x289`, `+0x9c`, and `+0x98` are not given meanings: the packet claims only the order and outcomes of the checks on them.
- The two naming slots' tables, and whether any indirect caller reaches this window through them, are unknown and not modeled.

## Unknowns

- What struct this pointer points to, and what any of the five fields denote.
- Whether the nearby cluster windows (`0x5382c90`, `0x5382d30`) are methods of the same struct or table, and what their relationship to this window is.
- Whether any indirect caller reaches this window; the direct-call scan cannot answer that.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
