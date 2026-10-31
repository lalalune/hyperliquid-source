# foundation-magic-tag-tail-dispatch-94: what does the 41-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 41-byte FDE window, its 7 int3 padding bytes, the magic-tag dispatch rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the magic tag value, the tail targets' behavior, the caller's behavior beyond the call itself, other tail-dispatch helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a two-way tail dispatch gated on an exact 64-bit magic tag. Its distinctive property is that the dispatch key is not a small tag byte but a full qword compared against the constant `0x800000000000002a`, and the two dispatch paths adjust the pointer differently (by 0x10 on the magic path, by 8 on the fall-through path) before jumping to two different tail targets. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4340e00`, no open pull request title mentions it or magic-tag-tail-dispatch, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

Weakness, stated head-on: this window is dispatch-only — it stores nothing, returns no value (both paths tail-jump), and its rule is a single two-way branch. It is bound because the rule is exact and fully locked (every instruction byte, both tail targets' FDE records, the caller, and the relocation scan), not because the rule is rich. The round-10 scout flagged it as weak backup material for exactly this reason, and the packet does not overstate it.

Family caution, addressed head-on: this window is in the same broad tag-dispatched-tail-gate class as packet #62's two-path tail gate (0x1fc7780), packet #66's quirky tag gate (0x223e3a0), and packet #67's multi-path tail dispatcher (0x4341b60). It is bound on its own merits, not as a family member or sibling of any of them: its dispatch key is a 64-bit magic constant rather than a tag byte, it has exactly two tail targets (not one or three), and neither path returns. No census of the class is claimed, and no shared-primitive decode is attempted.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_magic_tag_tail_dispatch.py --check research/work-items/foundation-magic-tag-tail-dispatch-94/evidence.json
python3 -m unittest tests.test_foundation_magic_tag_tail_dispatch -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4340e00 --stop-address=0x4340e30 artifacts/node/94/hl-node
objdump -d --start-address=0x43848f0 --stop-address=0x4386a36 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its padding. The `caller.objdump.txt` file retains complete disassembly of the confirmed caller FDE. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x1e3c50`, the next FDE at `0x1e3c64`, the caller FDE at `0x55611c`, and the two tail-target FDEs at `0x1e3e60` and `0x5513b0`. The checker locks these raw FDE records and their shared CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1e3c50` describes `[0x4340e00, 0x4340e29)`, 41 bytes (CIE at offset 0, `zR` pcrel sdata4: field VA `0xec5170` + `0x347bc90` = `0x4340e00`, range `0x29`). GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x4340e24` ends at `0x4340e29`).
- The padding is exactly 7 bytes of `int3` (`0xcc`), from `0x4340e29` to `0x4340e30`: the next FDE starts at `0x4340e30` (`[0x4340e30, 0x4340f58)`, 0x128 bytes); the checker locks the padding bytes and the next FDE's PC/range separately. The 48-byte stride (41 + 7) is not the FDE extent, and any description of this window with a 48-byte body would overstate the frame.
- The window opens directly with the pointer computation — no `endbr64` (an observation, not a scout deviation).

### Body behavior: magic-tag tail dispatch, two targets, no return

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
|----|-------------|------|
| `0x4340e00` | `lea 0x8(%rdi),%rax` | Precompute `rdi + 8` (the fall-through argument) |
| `0x4340e04` | `cmpb $0x0,(%rdi)` | First byte must be zero |
| `0x4340e07` | `jne 0x4340e21` | Nonzero first byte → fall-through path |
| `0x4340e09` | `movabs $0x800000000000002a,%rcx` | Magic constant |
| `0x4340e13` | `cmp %rcx,(%rax)` | Compare qword at `[rdi+8]` against magic |
| `0x4340e16` | `jne 0x4340e21` | Non-magic qword → fall-through path |
| `0x4340e18` | `add $0x10,%rdi` | Magic path: advance pointer by 0x10 |
| `0x4340e1c` | `jmp 0x434b140` | Magic path tail target |
| `0x4340e21` | `mov %rax,%rdi` | Fall-through path: argument is `rdi + 8` |
| `0x4340e24` | `jmp 0x434aa10` | Fall-through tail target |

Rule, stated exactly:

- byte `[rdi] == 0` **and** qword `[rdi+8] == 0x800000000000002a` → `rdi += 0x10`, tail-jump to `0x434b140`.
- Otherwise (first byte nonzero, or qword differs, or both) → `rdi += 8`, tail-jump to `0x434aa10`.

There is no plain return path: every input tail-jumps to one of the two targets. Note the asymmetry the bytes force: the magic path advances by 0x10 (past both checked fields), while the fall-through path advances by only 8 (past the first byte field alone, reusing the precomputed `lea` result). The checker locks both adjustments and both targets; it does not smooth the asymmetry into a single rule.

### Tail targets: named, not decoded

Both tail targets are FDE starts, locked in the checker and retained in `frames.txt`, with no claim about what they do with the adjusted argument:

- `0x434aa10` → `[0x434aa10, 0x434aa8b)`.
- `0x434b140` → `[0x434b140, 0x434b25e)`.

### Incoming calls: one direct caller, boundary-confirmed

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site targeting this window — `0x4386969` (bytes `e8 92 a4 fb ff`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x43848f0..0x4386a36`): the preceding instruction is `lea 0x2e0(%rsp),%rdi` ending exactly at `0x4386969`, so the call site is not a mid-instruction false positive. Caller setup locked: `lea 0x2e0(%rsp),%rdi` immediately before the call. Caller purpose beyond the call itself is not claimed. The scan is explicitly not a complete xref census: indirect reachability is neither claimed nor excluded.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries, counts locked by the checker).

### Scout precision

No scout correction needed: every scouted element verified exactly (FDE range, 41-byte body, 7 padding bytes, both tail paths and targets, the one caller and its FDE range, no naming relocation). Nearest claimed window: three-field tail gate `0x473b120` (packet #48), `0x3fa320` away.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0xc67000` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences (kept separate from observations)

- The label "magic-tag tail dispatch" is an inference from the observed rule (a full-qword magic comparison selecting between two tail jumps). It is not a source-level name.
- The two fields at offsets 0 and 8 are not given meanings: the packet claims only that the first byte and the following qword are the dispatch key.
- The tail targets' behavior, and what the adjusted pointer means to them, is unknown and not modeled.

## Unknowns

- What struct this pointer points to, and what the magic value `0x800000000000002a` denotes.
- Whether the fall-through target (`0x434aa10`) and the magic target (`0x434b140`) share code or are independent handlers.
- Whether any indirect caller reaches this window; the direct-call scan cannot answer that.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
