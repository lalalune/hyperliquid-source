# Foundation sysconf threshold gate (node #94)

A 48-byte single-call window at `0x5335bf0` that calls `sysconf` (via the
PLT stub at `0x5660210`) with `edi = 30`, applies a threshold gate to the
signed return value, stores the result to a `.bss` global, and returns.
One call, one compare, one conditional move, one store: no branch, no loop,
no second call, no constant pool. The callee's behavior is excluded from
the rule; only its identity is locked.

## Rule

Call `sysconf` (PLT stub `0x5660210`) with `edi = 30` (other argument
registers pass through), then store `(signed ret <= 0x3ff ? 0x1000 : ret)`
as a qword to `.bss` address `0x578f8a0`, then `ret`.

In other words: a small result (at most 1023, including negative results)
is floored up to 4096; anything larger is stored unchanged.

## Window

| Field | Value |
| --- | --- |
| Start | `0x5335bf0` |
| End (exclusive) | `0x5335c20` |
| Size | 48 bytes |
| FDE section offset | `0x002afe8c` |
| FDE CIE | `0x00000000` |
| Padding | 0 bytes (the next FDE starts immediately at `0x5335c20`) |
| Body SHA-256 | `76f470b82e265dfcc45e997f5c26b4af1b3efdf303b4e479bb2bed32d2656e2d` |
| Target | node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Worktree HEAD | `2993e46` |

Instruction walk, in order:

| Address | Instruction | Role |
| --- | --- | --- |
| `0x5335bf0` | `endbr64` | Entry marker |
| `0x5335bf4` | `sub rsp, 8` | Stack alignment scratch |
| `0x5335bf8` | `mov edi, 0x1e` | First argument: 30 |
| `0x5335bfd` | `call 0x5660210` | The single call; PLT stub for `sysconf` |
| `0x5335c02` | `mov edx, 0x1000` | Floor value 4096 |
| `0x5335c07` | `cmp rax, 0x3ff` | Compare signed return against 1023 |
| `0x5335c0d` | `cmovle rax, rdx` | If `ret <= 1023` (signed), take 4096 |
| `0x5335c11` | `lea rdx, [rip+0x459c88]` | `.bss` global at `0x578f8a0` |
| `0x5335c18` | `mov [rdx], rax` | Store the gated result |
| `0x5335c1b` | `add rsp, 8` | Restore stack |
| `0x5335c1f` | `ret` | Return (no tail jump) |

The comparison is signed (`cmovle` after `cmp`): a negative return value
is below the threshold and is floored to 4096, exactly like 0.

## Callee

The call target is not an FDE function: it is the 16-byte PLT stub for the
`sysconf` import.

| Field | Value |
| --- | --- |
| Start | `0x5660210` (in `.plt`, `0x56600e0..0x5661250`) |
| Size | 16 bytes (stub only) |
| Stub bytes | `ff251a8c11006812000000e9c0feffff` |
| Stub SHA-256 | `04eb853e43cc64be6cfc060a3ff445c55c41c26b108d34540b66f632f6e34ffd` |
| GOT slot | `0x5778e30` (in `.got.plt`, value `0x5660216`, i.e. lazy binding unresolved) |
| Relocation | `.rela.plt` entry, `r_offset = 0x5778e30`, type 7 (`R_X86_64_JUMP_SLOT`), symbol `sysconf` |
| FDE | None: no FDE covers `0x5660210` (the last FDE before it ends at `0x56600b0`, and no FDE starts after it in `.plt`) |

The import name comes from the binary's own relocation record
(`.rela.plt` + `.dynsym` + `.dynstr`), not from a nearest-symbol
annotation: GNU objdump independently renders the call target as
`<sysconf@plt>`. The callee's behavior is excluded from the rule; the
stub bytes, GOT slot, and relocation record lock its identity, which is
all the rule uses.

The stub is called from 4 direct sites in `.text`: this window
(`0x5335bfd`) and three sites inside two larger functions (`0x54ba193`
and `0x54ba1a0` inside `0x54b9f30..0x54ba755`, 2085 bytes; `0x552d6e5`
inside `0x552d6c0..0x552db37`, 1143 bytes). Only this window is a small
single-call window, so the shared import is not a shared rule.

## Neighbors

| FDE start | Size | Relation |
| --- | --- | --- |
| `0x5335900` | 302 bytes | Previous FDE; unrelated |
| `0x5335c20` | 12 bytes | Next FDE; unrelated |

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x5335bf0`
finds exactly zero sites, so this packet has seven files (no
`caller.objdump.txt`). Register-indirect references, other pointer paths,
prefixes, and data sections are not a complete xref census, so the claim
is scoped to direct `e8` calls, not to all possible references.

## Twins and uniqueness

Raw FDE bytes, position-wise equal bytes, no normalization. Two claimed
cohorts are reported: A = claimed windows present in the 20–150B
single-call census (29 windows); B = every claimed window from every
`evidence.json` in prior worktrees and the main tree (31 windows).

- Against claimed windows: maximum similarity 0.250 on the max-length
  measure (cohort A: at `0x54d6360`; cohort B: at `0x55243d0`, the
  div-million window, whose best min-length score is 0.316), well below
  the 0.60 cutoff.
- Against the full corpus of 31,898 single-call FDE windows: best
  non-self 0.438 max-length (at `0x5447780`, 48 bytes: another PLT-call
  wrapper that zeroes a struct at the returned pointer — different
  callee, different rule, no gate) and 0.500 min-length with the 20-byte
  floor (at `0x55204b0`, 20 bytes: a call-then-zero wrapper that shares
  only the 10-byte prologue over its short length).
- The mnemonic skeleton
  (`endbr64 sub mov call mov cmp cmovle lea mov add ret`) is a
  singleton among 31,898 single-call FDE windows of 20–150 bytes, and
  this window is the only single-call census window calling `0x5660210`.
- Measure validation: the same procedure reproduces #151's claimed-best
  0.211 max / 0.235 min (against `0x552fbe0`, the #137 window) and the
  corpus-best 0.333 / 0.439 exactly. For #150 it gives 0.279 against
  `0x4f9ee90` (the #147 window), not #150's reported 0.256 against #127:
  #150's claimed cohort missed #147. Either value is far below 0.60, so
  the conclusion is unchanged; the full-cohort value is reported here.

## Rule edges

| Return value | Model | Stored |
| --- | --- | --- |
| `0x0` | `0 <= 1023` | `0x1000` |
| `0x3ff` | `1023 <= 1023` (boundary) | `0x1000` |
| `0x400` | `1024 > 1023` | `0x400` |
| `0x1000` | coincides with the floor | `0x1000` |
| `0xffffffffffffffff` (-1 signed) | negative `<= 1023` | `0x1000` |
| `0x7fffffffffffffff` | largest positive, kept | `0x7fffffffffffffff` |
| `0x8000000000000000` (signed minimum) | negative `<= 1023` | `0x1000` |

The edges are model checks on the recorded arithmetic, not executions
of the target binary.

## Reading (interpretation, not part of the rule)

The constants are consistent with a cached page-size query: argument 30,
a 1023 threshold, and a 4096 floor. That reading is not claimed by the
rule, which stands on the recorded bytes, the relocation record, and the
gate arithmetic alone.

## Rejected candidates

| Address | Reason |
| --- | --- |
| `0x5650a60` (88 bytes) | Real computation (nonzero flag via a bit trick, call + tail jump to the same callee), kept as backup behind this window: the gate here is smaller and more directly readable. |
| `0x52cc080` / `0x52cf2f0` (43 bytes each) | Call-result-plus-one tail-jump wrappers; a two-member family, and a single `+1` is too thin for a standalone packet. |
| `0x4ff3f90` (60 bytes) | Static-pointer stores (struct-init adjacent) plus a tail jump into the `0x5660440` PLT-stub family. |
| `0x5163410` / `0x5391810` / `0x5468630` | Static-pointer stores (struct-init adjacent), no value computation. |
| `0x5524370` / `0x53a9820` / `0x5157b70` | Argument shuffling / restore with no value computation (adapters). |
| `0x5157b50` / `0x5155fb0` | Call then constant `1` return (thin wrappers). |
| `0x4f9de40` | Argument marshalling for a call, no post-call computation. |
| `0x5335fa0` | Call-result store mixed with struct zeroing. |

## Limits

- The callee's behavior is excluded; only the PLT stub identity
  (bytes, GOT slot, relocation symbol) is locked.
- The gate comparison is signed: negative returns floor to 4096.
- The window has no tail jump: the stored global is the window's only
  observable effect in this packet.
- Nearest-symbol annotations from the disassembler carry large offsets
  and are not identifications; the `sysconf` name here comes from the
  relocation record, not from a nearest-symbol annotation.
- The zero-caller claim covers direct `e8` calls in `.text` only.

## Checker and tests

Reproduce from the repository root:

```
python3 tools/foundation_sysconf_gate.py \
  --check research/work-items/foundation-sysconf-gate-94/evidence.json
python3 -m unittest tests.test_foundation_sysconf_gate -v
```

The checker re-derives the window body, its zero padding, the three
retained FDE records (window, next, previous), the PLT stub bytes, the
GOT slot and its relocation record naming `sysconf`, the call and store
encodings, the gate rule on its edges, the callee's four direct call
sites, and the zero-caller scan from target bytes. The unit tests run
the checker on the real evidence plus corruption controls: each control
mutates one recorded fact (body hash, FDE offsets, call target, PLT
stub bytes, GOT slot, relocation symbol, store address, gate threshold
or floor, edge values, caller lists, padding) and must make the checker
fail.

## Files

- `README.md` (this file)
- `evidence.json`
- `window.objdump.txt` (GNU disassembly of the window and the PLT stub)
- `frames.txt` (FDE excerpts for the window, the next FDE, and the
  previous FDE)
- `MANIFEST.sha256`
- `tools/foundation_sysconf_gate.py`
- `tests/test_foundation_sysconf_gate.py`
