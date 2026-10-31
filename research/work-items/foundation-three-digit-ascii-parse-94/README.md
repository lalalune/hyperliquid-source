# foundation-three-digit-ascii-parse-94: what does the three-digit ASCII parse window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 85-byte FDE window with eleven padding bytes, the strict 3-character ASCII decimal parse rule with its exact leading-zero rejection, the exact incoming-call scan result (one direct site, boundary-confirmed), and the no-naming-relocation scan result.
- Excluded: what the parsed number means, the identity or purpose of the caller, any wider parse family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a strict three-digit ASCII decimal parse with no leading zero. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1683670`, no open pull request title mentions it or three-digit-ascii-parse, and its bytes overlap nothing in packets #1–#82.

## Scout note

The round-13 scout note listed this window (ranked #1, the round's best item) with FDE `[0x1683670, 0x16836c5)`, 85 bytes, 11 padding bytes, one direct caller at `0x1682606` (caller FDE `0x1682220..0x1682735`), no naming relocation, and nearest claimed window multiply-xor mixer loop `0x16488e0` (packet #82) `0x3ad90` away. Every element verified exactly, including the full body, both branch targets, the one caller site and its setup, and the zero naming relocations. No numeric correction to the scout's numbers was needed. One further observation, not a scout deviation since the scout did not claim it: unlike most packets, this window does NOT open with `endbr64`; its first instruction is `cmp $0x3,%rsi`.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_three_digit_ascii_parse.py --check research/work-items/foundation-three-digit-ascii-parse-94/evidence.json
python3 -m unittest tests.test_foundation_three_digit_ascii_parse -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1683670 --stop-address=0x16836d0 artifacts/node/94/hl-node
objdump -d --start-address=0x1682220 --stop-address=0x1682735 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its eleven padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x24804` (this window), `0x31f714` (the next FDE), and `0x31f3a8` (the caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x24804` describes `[0x1683670, 0x16836c5)`, 85 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Eleven `int3` bytes follow: the next FDE starts exactly at `0x16836d0` (record at `.eh_frame+0x31f714`, range to `0x1683ab9`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does NOT open with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x3924790`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: strict three-digit ASCII decimal parse, no calls, two branches

Inputs (System V order): `rdi` = base pointer, `rsi` = length. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1683670` | `cmp $0x3,%rsi` | Length must be exactly 3 |
| `0x1683674` | `jne 0x16836a6` | Length mismatch → invalid path |
| `0x1683676` | `movzbl (%rdi),%ecx` | b0 = first byte |
| `0x1683679` | `movzbl 0x1(%rdi),%eax` | b1 = second byte |
| `0x168367d` | `add $0xd0,%al` | b1' = b1 − '0' mod 256 |
| `0x168367f` | `movzbl 0x2(%rdi),%edx` | b2 = third byte |
| `0x1683683` | `add $0xd0,%dl` | b2' = b2 − '0' mod 256 |
| `0x1683686` | `lea -0x3a(%rcx),%esi` | b0 − 0x3a |
| `0x1683689` | `cmp $0xf7,%sil` | First-byte gate compare |
| `0x168368d` | `setb %sil` | sil = 1 iff b0 NOT in '1'..'9' |
| `0x1683691` | `cmp $0xa,%al` | Second-byte gate compare |
| `0x1683693` | `setae %dil` | dil = 1 iff b1 not a digit |
| `0x1683697` | `cmp $0xa,%dl` | Third-byte gate compare |
| `0x168369a` | `setae %r8b` | r8b = 1 iff b2 not a digit |
| `0x168369e` | `or %dil,%r8b` | Combine digit flags |
| `0x16836a1` | `or %sil,%r8b` | Combine with first-byte flag |
| `0x16836a4` | `je 0x16836a9` | All flags zero → compute path |
| `0x16836a6` | `xor %eax,%eax` | Invalid: result 0 |
| `0x16836a8` | `ret` | |
| `0x16836a9` | `movzbl %dl,%edx` | b2' zero-extended |
| `0x16836ac` | `add $0xd0,%cl` | b0' = b0 − '0' mod 256 |
| `0x16836af` | `movzbl %cl,%ecx` | b0' zero-extended |
| `0x16836b2` | `imul $0x64,%ecx,%ecx` | Hundreds term |
| `0x16836b5` | `movzbl %al,%eax` | b1' zero-extended |
| `0x16836b8` | `add %eax,%eax` | Tens × 2 |
| `0x16836ba` | `lea (%rax,%rax,4),%eax` | Tens × 10 |
| `0x16836bd` | `movzbl %al,%eax` | Tens term byte-truncated |
| `0x16836c0` | `add %ecx,%eax` | Add hundreds |
| `0x16836c2` | `add %edx,%eax` | Add ones |
| `0x16836c4` | `ret` | |

Rule: if `rsi != 3`, return 0. Else let `b0 = [rdi]`, `b1 = [rdi+1]`, `b2 = [rdi+2]`. Return 0 unless `b0` is in `'1'..'9'` AND `b1`, `b2` are in `'0'..'9'`. On the valid path return `(b0 − '0') * 100 + (b1 − '0') * 10 + (b2 − '0')`.

The first-byte gate deserves exact statement, because it is easy to misread as "b0 is a digit": the flag is `sil = ((b0 − 0x3a) mod 256 < 0xf7)`. For `b0` in `'1'..'9'` (`0x31..0x39`), `b0 − 0x3a` is `0xf7..0xff`, which is NOT less than `0xf7`, so `sil = 0`. For every other byte value — including `'0'` (`0x30 − 0x3a = 0xf6 < 0xf7`), `':'` (`0`), and bytes above `'9'` (`1..` up to the wrap) — `sil = 1`. So a leading `'0'` is REJECTED, and a 0 return unambiguously means invalid, since valid inputs give `100..999`.

The tens-term truncation (`movzbl %al,%eax` after the ×10) is exact on the valid path: the tens digit is at most 9, so the tens term is at most 90, below 256. It would only matter for an invalid tens digit, which the gate already excludes.

Worked edges (hand-computed from the trace above):

- `n = 0`, `n = 2` (`"12"`), `n = 4` (`"1234"`) → `0` (length gate).
- `"123"` → `123`; `"100"` → `100`; `"999"` → `999`; `"523"` → `523`.
- `"012"` → `0` (leading zero rejected); `":23"` → `0`; `" 23"` → `0`.
- `"12a"` → `0` (ones digit gate); `"1:3"` → `0` (tens digit gate).

### Incoming calls: one direct site, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site whose rel32 lands on the window start: `0x1682606` (bytes `e8 65 10 00 00`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x1682220..0x1682735`). This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. Caller setup locked: `mov 0x8(%rdi),%edi` immediately before the call's length setup `mov 0x10(%r15),%rsi`; caller purpose not claimed.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The window is labeled "three-digit ASCII parse" for convenience. The label is an inference from the observed operations, kept separate from the rule above.
- The length input and the three input bytes are read as a strict decimal parse, but no parsed-number meaning, field type, or source-level function is claimed — the bytes show a parse, not its purpose.

## Unknowns

- What the parsed number means, and what the caller does with the result.
- Whether any indirect caller or tail-jump entrant reaches this window beyond the one direct site found.
- Whether the window belongs to a wider parse family.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
