# foundation-bounded-scaled-cursor-advance-94: what does the bounded scaled cursor advance window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 54-byte FDE window with ten padding bytes, the bounded scaled cursor advance rule with its exact fields and wrapping arithmetic, the exact incoming-call scan result (zero direct sites), and the single naming relocation slot.
- Excluded: what the struct fields mean, what the cursor advances over, what consumes the returned remainder, any wider cursor-advance family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a cursor advance bounded by a scaled count, returning the unadvanced remainder, with one field written and no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4ea41e0`, no open pull request title mentions it or bounded-scaled-cursor-advance, and its bytes overlap nothing in packets #1–#111.

## Scout note

The round-17 scout note listed this window (ranked #3, richest rule of the round) with FDE `[0x4ea41e0, 0x4ea4216)`, 54 bytes, 10 padding bytes, zero direct callers, one naming relocation slot (`0x574faf8`), and nearest claimed window conditional 16-byte restore `0x4e6cf10` (packet #102) `0x372d0` away. Every element verified exactly; no correction was needed.

## Caveats, stated head-on

- **Component-cluster caveat.** This window sits inside a four-window `0x4ea41xx` cluster sharing the 88-byte stride: `0x4ea41b0`/`0x4ea4270` (scaled-count inits, a twin pair) and `0x4ea4220` (an 88-byte element copy step). Only this window's min-clamp advance rule is claimed. Nothing is claimed about the container, the other three windows, or what the 88-byte stride elements are. Byte-compare against the cluster siblings confirms this window is not one of them: 5/44 bytes vs `0x4ea41b0`, 3/45 vs `0x4ea4270`, 8/54 vs `0x4ea4220` — different rule, different length, not a twin.
- **Magic-factor caveat.** The purpose of the `0x2e8ba2e8ba2e8ba3` factor is NOT claimed. The checker locks only the literal arithmetic the bytes show: count multiplied by that constant (low 64 bits), then a min-clamp against the input. No division, bucket, or scaling meaning is asserted.
- **Thinness, stated plainly.** This is a single-purpose window: one count, one multiply, one min, one advance, one return. What it is not is ambiguous — the field offsets, the multiply constant, the unsigned min, and the 88-byte advance are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bounded_scaled_cursor_advance.py --check research/work-items/foundation-bounded-scaled-cursor-advance-94/evidence.json
python3 -m unittest tests.test_foundation_bounded_scaled_cursor_advance -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4ea41e0 --stop-address=0x4ea4220 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its ten padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x27c87c` (this window) and `0x27c890` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x27c87c` describes `[0x4ea41e0, 0x4ea4216)`, 54 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Ten `int3` bytes follow: the next FDE starts exactly at `0x4ea4220` (record at `.eh_frame+0x27c890`, range to `0x4ea4269`). The unwind-index stride is therefore 64 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `mov %rsi,%rax`, not `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x4ea41e0`.

- Offset `0x00`: `mov %rsi,%rax` — input preserved in rax.
- Offset `0x03`: `mov 0x8(%rdi),%rcx` — cursor load.
- Offset `0x07`: `mov 0x18(%rdi),%rdx` — end load.
- Offset `0x0b`: `sub %rcx,%rdx` — span: rdx = end − cursor (wrapping).
- Offset `0x0e`: `shr $0x3,%rdx` — count: rdx = span >> 3 (logical shift).
- Offset `0x12`: `movabs $0x2e8ba2e8ba2e8ba3,%rsi` — the literal factor.
- Offset `0x1c`: `imul %rdx,%rsi` — scaled: rsi = count × factor (low 64 bits).
- Offset `0x20`: `cmp %rsi,%rax` — compare input against scaled.
- Offset `0x23`: `cmovb %rax,%rsi` — taken: if input < scaled (unsigned), rsi = input; else rsi stays scaled. So taken = min(input, scaled).
- Offset `0x27`: `imul $0x58,%rsi,%rdx` — advance bytes: rdx = taken × 88.
- Offset `0x2b`: `add %rcx,%rdx` — new cursor: rdx += old cursor.
- Offset `0x2e`: `mov %rdx,0x8(%rdi)` — cursor store: the only field written.
- Offset `0x32`: `sub %rsi,%rax` — remainder: rax = input − taken.
- Offset `0x35`: `ret` — single return on every path.

### Decoded rule

Let `cursor = [rdi+8]`, `end = [rdi+0x18]`, `input = rsi`, all qwords. Then `count = (end − cursor) >> 3` (wrapping subtract, logical shift); `scaled = count × 0x2e8ba2e8ba2e8ba3` (low 64 bits); `taken = min(input, scaled)` (unsigned); `[rdi+8] = cursor + taken × 88` (wrapping); return `input − taken` (wrapping). No other field is written on any path.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x574faf8` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The slot is reported as a list only; no meaning is claimed for it, and the contents it points at are not claimed.

## Inferences

- The "bounded scaled cursor advance" label is an inference from the observed rule, kept separate from the rule itself.
- The 88-byte stride is shared with the neighboring cluster windows, but no element type, container, or consumer is inferred from it.

## Unknowns

- What the struct at `rdi` is, what the cursor advances over, and what consumes the returned remainder.
- Why the factor `0x2e8ba2e8ba2e8ba3` is what it is; its purpose is explicitly unclaimed.
- Whether any caller reaches this window indirectly; the scan covers direct `e8` sites only.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
