# foundation-three-valued-byte-dword-gate-94: what does the 31-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 31-byte FDE window, its 1 int3 padding byte, the three-valued byte/dword gate rule, the two naming slots, and the zero-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the two naming slots, the nearby cluster windows' behavior, other byte/dword gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a gate that returns 1 on a nonzero first byte, and otherwise returns 2 exactly when a dword field equals 1. Its distinctive property is the three-valued return set — {1} ∪ {0, 2} — which must not be collapsed into a boolean: the first-byte path and the dword path produce different nonzero values, and the checker locks that distinction. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5382c90`, no open pull request title mentions it or three-valued-byte-dword-gate, and its bytes overlap nothing in packets #1–#72.

Cluster caution, addressed head-on: two nearby windows (`0x5382d50`, packet #70, and `0x5382d30`, an unbuilt backup candidate; adjacent FDEs in the same field neighborhood at offsets `+0x28a`/`+0x289`/`+0x290`/`+0x98`/`+0x9c`) read the same fields this window reads, and they look like sibling methods of one struct or table. This packet binds ONLY `0x5382c90`; the cluster members are not built here (packet #70 already binds `0x5382d50` with the same mutual disclosure), no census of the cluster is claimed, and building the remaining member alongside these windows is a parent decision, not something this packet assumes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_three_valued_byte_dword_gate.py --check research/work-items/foundation-three-valued-byte-dword-gate-94/evidence.json
python3 -m unittest tests.test_foundation_three_valued_byte_dword_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5382c90 --stop-address=0x5382cb0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x2b2f18` and the next FDE at `0x2b2f2c`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b2f18` describes `[0x5382c90, 0x5382caf)`, 31 bytes (CIE at offset 0, `zR` pcrel sdata4: field VA `0xf94438` + `0x43ee858` = `0x5382c90`, range `0x1f`). GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5382cae` ends at `0x5382caf`).
- The padding is exactly 1 byte of `int3` (`0xcc`), from `0x5382caf` to `0x5382cb0`: the next FDE starts at `0x5382cb0` (`[0x5382cb0, 0x5382cb9)`, 9 bytes); the checker locks the padding byte and the next FDE's PC/range separately. The 32-byte stride (31 + 1) is not the FDE extent, and any description of this window with a 32-byte body would overstate the frame.
- The window opens with `endbr64`.

### Body behavior: three-valued byte/dword gate

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
|----|-------------|------|
| `0x5382c90` | `endbr64` | Entry marker |
| `0x5382c94` | `cmpb $0x0,0x28a(%rdi)` | First byte must be zero to continue |
| `0x5382c9b` | `mov $0x1,%eax` | Stage the first-byte return value (1) |
| `0x5382ca0` | `jne 0x5382cae` | Nonzero first byte → return 1 |
| `0x5382ca2` | `cmpl $0x1,0x28c(%rdi)` | Dword at +0x28c must equal 1 |
| `0x5382ca9` | `sete %al` | 1 exactly when the dword equals 1, else 0 |
| `0x5382cac` | `add %eax,%eax` | Double: 2 on equality, 0 otherwise |
| `0x5382cae` | `ret` | Shared return: 1, 2, or 0 |

Rule, stated exactly:

- byte `[rdi+0x28a] != 0` → return 1.
- Otherwise → return 2 exactly when dword `[rdi+0x28c]` equals 1, else 0.

Note the two details the bytes force: the `mov $0x1,%eax` before the branch means the first-byte path returns 1 without touching the dword, and the same `mov` clears the upper bits of `eax` before `sete`, so the doubled value is exactly 0 or 2 — there is no stale-high-byte caveat. The return set is exactly {1} ∪ {0, 2}; collapsing it to a boolean would erase the distinction between the two nonzero outcomes, and the checker locks all three values separately.

### Incoming calls: zero direct callers

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites targeting this window — explicitly not a complete xref census: indirect reachability (including through whatever tables hold the two naming slots below) is neither claimed nor excluded.

### Data edge: two naming slots, not one

Exactly two relocation records of any type in any `.rela.*` section name this window as addend, both `R_X86_64_RELATIVE` in `.rela.dyn`: slots `0x5763318` and `0x5778ae0`. The checker locks exactly this two-slot list (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked). This is reported as a slot list, not a single naming slot, and nothing about the tables that hold these slots — their layout, purpose, or relationship to this window — is claimed.

### Scout precision

No scout correction needed: every scouted element verified exactly (FDE range, 31-byte body, 1 padding byte, both rule paths including the `endbr64` open, zero direct callers, the two naming slots, nearest claimed window). Nearest claimed window: two-hop field select `0x5361710` (packet #65), `0x21580` away.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0x3dae90` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences (kept separate from observations)

- The label "three-valued byte/dword gate" is an inference from the observed rule (a byte gate yielding 1, and a dword-equality gate yielding 2 or 0). It is not a source-level name.
- The two fields at offsets `+0x28a` and `+0x28c` are not given meanings: the packet claims only the order and outcomes of the checks on them.
- The two naming slots' tables, and whether any indirect caller reaches this window through them, are unknown and not modeled.

## Unknowns

- What struct this pointer points to, and what either of the two fields denotes.
- Whether the nearby cluster windows (`0x5382d50`, `0x5382d30`) are methods of the same struct or table, and what their relationship to this window is.
- Whether any indirect caller reaches this window; the direct-call scan cannot answer that.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming slots do not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).

## Weakness, stated head-on

This is a small gate — 31 bytes, two fields read, no store, no direct caller found. It is bound because the rule is exact and fully locked (including the three-valued return distinction), not because it is rich.
