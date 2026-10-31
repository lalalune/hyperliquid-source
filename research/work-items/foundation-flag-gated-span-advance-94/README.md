# foundation-flag-gated-span-advance-94: what does the flag-gated bounds-checked span advance window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 71-byte FDE window with nine padding bytes, the flag-gated bounds-checked span advance rule with its exact fields and wrapping arithmetic, the exact incoming-call scan result (zero direct sites), the zero naming relocation slots, and the gate-prefix uniqueness result.
- Excluded: what the struct fields mean, what the span field represents (length vs end position), what consumes the rewritten field, any wider span-advance family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a span field is rewritten only when a flag byte is clear and two bounds checks pass, with one field written and no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5293e00`, no open pull request title mentions it, and its bytes overlap nothing in packets #1–#115.

## Scout note

The round-20 scout note listed this window (ranked #1, the round's only rankable item) with FDE `[0x5293e00, 0x5293e47)`, 71 bytes, 9 padding bytes, zero direct callers, zero naming relocation slots, nearest claimed window three-field span sum `0x5276b80` (packet #111) `0x1d280` away, and the gate prefix (endbr64 + cmpb $0, 0x28(%rsi)) occurring exactly once in all of `.text`. Every element verified exactly except one correction below.

## Scout correction, stated head-on

The scout note described the span-end gate as "span_start + span_len <= cursor -> ret". The bytes say otherwise: `cmp %rdi,%r9` followed by `jae` to ret means ret when span_start + span_len >= cursor (unsigned, on the wrapping sum), so the field is rewritten only when the sum is strictly below the cursor. The two rules agree at equality (both ret) and disagree everywhere else: above the cursor the scout's note would write and the bytes ret; below the cursor the scout's note would ret and the bytes write. The README and checker lock the bytes' rule, not the scout's description. The scout's remaining elements needed no correction.

## Caveats, stated head-on

- **Packet #112 distinction, stated head-on (mandatory).** Packet #112 (`0x4ea41e0` bounded scaled cursor advance) shares only the words "cursor advance" with this window. Different VA, different stride (112 vs 88), different rule (flag gate + two bounds checks + field rewrite vs min-clamp + cursor advance + remainder return), different fields. Byte-compare over the 54-byte overlap: 0/54 identical — not a twin. The PR title leads with the gate, not the word "cursor", to avoid confusion.
- **Field-meaning caveat.** What the `[elem+0x18]` field MEANS (a length, an end position, or something else) is explicitly unclaimed. The checker locks only the literal arithmetic: the field is rewritten to `[rsi+0x20] + span_len`, whatever that value denotes.
- **Gate-prefix uniqueness, stated plainly.** The gate prefix (endbr64 + cmpb $0, 0x28(%rsi)) occurs exactly once in all of `.text` — this window. The x112 indexing idiom appears mid-function in larger routines nearby (e.g. `0x5294513`, NOT an FDE start) — idiom reuse, not a window population. Neighbouring FDEs in `[0x5293000, 0x5295000]` are all calls/excluded/fragment windows (nearest: `0x5293d80` calls, `0x5293e50` indirect-jump fragment, `0x5293e80` calls, `0x5294c30` tail-jump-to-free `0x5660440`) — no sibling window shares this rule.
- **Provenance, stated plainly.** This window was found in the round-20 general slice, NOT in any peer lane. The peer lanes themselves yielded zero rankable easy windows this round; this packet does not claim peer-lane coverage.
- **Thinness, stated plainly.** This is a single-purpose window: one flag gate, one indexed element, two bounds checks, one field rewrite, one return. What it is not is ambiguous — the flag offset, the 112-byte stride, the unsigned bounds compares, and the rewritten field are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_flag_gated_span_advance.py --check research/work-items/foundation-flag-gated-span-advance-94/evidence.json
python3 -m unittest tests.test_foundation_flag_gated_span_advance -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5293e00 --stop-address=0x5293e50 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its nine padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2a9b80` (this window) and `0x2a9b94` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a9b80` describes `[0x5293e00, 0x5293e47)`, 71 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Nine `int3` bytes follow: the next FDE starts exactly at `0x5293e50` (record at `.eh_frame+0x2a9b94`, range to `0x5293e73`). The unwind-index stride is therefore 80 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, followed immediately by the flag gate — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x5293e00`.

- Offset `0x00`: `endbr64` — entry.
- Offset `0x04`: `cmpb $0x0,0x28(%rsi)` — flag test.
- Offset `0x08`: `jne 0x5293e46` — flag gate: flag != 0 jumps to ret, nothing changed.
- Offset `0x0a`: `mov (%rdx),%edx` — index load (32-bit, zero-extended).
- Offset `0x0c`: `mov (%rsi),%r8` — base load.
- Offset `0x0f`: `mov 0x20(%rsi),%rcx` — offset load.
- Offset `0x13`: `lea 0x0(,%rdx,8),%rax` — index x 8.
- Offset `0x1b`: `sub %rdx,%rax` — index x 7.
- Offset `0x1e`: `shl $0x4,%rax` — index x 112.
- Offset `0x22`: `add (%rdi),%rax` — element address: rax = [rdi] + idx x 112.
- Offset `0x25`: `lea (%r8,%rcx,1),%rdi` — cursor: rdi = base + offset.
- Offset `0x29`: `mov 0x28(%rax),%rdx` — span start load.
- Offset `0x2d`: `mov 0x18(%rax),%rsi` — span length load.
- Offset `0x31`: `lea (%rdx,%rsi,1),%r9` — span end: r9 = span_start + span_len (wrapping).
- Offset `0x35`: `cmp %rdi,%r9` — compare span end against cursor.
- Offset `0x38`: `jae 0x5293e46` — span-end gate: span end >= cursor (unsigned) jumps to ret, nothing changed.
- Offset `0x3a`: `cmp %rdx,%r8` — compare base against span start.
- Offset `0x3d`: `jb 0x5293e46` — span-start gate: base < span_start (unsigned) jumps to ret, nothing changed.
- Offset `0x3f`: `add %rsi,%rcx` — field value: rcx = offset + span_len (wrapping).
- Offset `0x42`: `mov %rcx,0x18(%rax)` — field store: the only field written.
- Offset `0x46`: `ret` — single return on every path.

### Decoded rule

Let `flag = byte [rsi+0x28]`, `idx = [rdx]` (32-bit load, zero-extended), `elem = [rdi] + idx x 112` (wrapping), `cursor = [rsi] + [rsi+0x20]` (wrapping), `span_start = [elem+0x28]`, `span_len = [elem+0x18]`, all qwords unless noted. If flag != 0, return with nothing changed. If (span_start + span_len) mod 2^64 >= cursor (unsigned), return unchanged. If span_start < [rsi] (unsigned), return unchanged. Otherwise `[elem+0x18] = [rsi+0x20] + span_len` (wrapping) and return. No other field is written on any path; the return value is not claimed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller file is included for that reason.

### Data edge

Zero `R_X86_64_RELATIVE` records in any `.rela.*` section name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence is itself the retained result; no meaning is claimed for it.

### Gate-prefix uniqueness

The 8-byte gate prefix (endbr64 + cmpb $0, 0x28(%rsi)) occurs exactly once in all of `.text` — this window. The checker locks that uniqueness result alongside the body.

## Inferences

- The "flag-gated bounds-checked span advance" label is an inference from the observed rule, kept separate from the rule itself.
- The 112-byte stride is shared as an idiom with nearby larger routines, but no element type, container, or consumer is inferred from it.

## Unknowns

- What the struct at `rdi` is, what the `[elem+0x18]` field denotes, and what consumes the rewritten field.
- Whether any caller reaches this window indirectly; the scan covers direct `e8` sites only.
- Why the flag byte at `[rsi+0x28]` gates this rewrite; its purpose is explicitly unclaimed.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the zero-slot result does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
