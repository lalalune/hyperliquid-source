# foundation-keyword-classifier-gas-94: what does the input/gas_limit window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 86-byte FDE window, its ten int3 padding bytes, the two keyword immediates it compares against, one incoming direct call with argument setup, and the exact three-tag output rule.
- Excluded: the meaning of the leading output byte 9 and of the tags 0/1/2, the caller's behavior beyond its call site and argument setup, other keyword or string helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two length tests, two comparands readable in full, and three exhaustive output paths with no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x25903d0`, no open pull request title mentions it or keyword-classifier-gas, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Why a third tag-9 classifier is still an individual binding

This is the third window in the run whose output byte 0 is always 9, after packet #15 (`until` / `required_matches`) and packet #25 (`vip` / `mm`). It is bound on its own merits, not as part of a classifier population:

- The keyword pair is distinct: `input` (exact length 5) and `gas_limit` (exact length 9). Neither keyword appears in packet #15 or #25, and the two lengths differ from both earlier pairs.
- The comparison shape differs in detail: packet #15's long keyword is a 16-byte memory constant compared with SIMD, while this window's long keyword is an 8-byte immediate plus a single trailing-byte xor, and its short keyword is a 4-byte immediate plus a trailing-byte xor.
- The output rule is fully determined by this window's own bytes (two length tests, two immediates, three exhaustive stores), and the checker locks those bytes, not a shared pattern.

The big-slice classifier population found by round-9 scouting must not be mined further as a batch: this packet is the last classifier in the round-9 queue, and any further classifier window needs its own individual justification, not membership in the population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_keyword_classifier_gas.py --check research/work-items/foundation-keyword-classifier-gas-94/evidence.json
python3 -m unittest tests.test_foundation_keyword_classifier_gas -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x25903d0 --stop-address=0x2590430 artifacts/node/94/hl-node
objdump -d --start-address=0x18fa9e0 --stop-address=0x18faa10 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site region of the caller FDE window (argument setup, call, and following bytes); the full caller FDE is `[0x18f9940, 0x18fb1d2)`, 7,058 bytes, and only that region is claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x93570`, the caller FDE at `0x32d4bc`, and the next FDE at `0x3ed644`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x93570` describes `[0x25903d0, 0x2590426)`, 86 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x2590425` is inside the FDE).
- The unwind index stride to the next entry is 96 bytes, ending at `0x2590430`, only because ten `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those ten padding bytes, and the checker locks the 86-byte body and the padding separately.
- No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x18fa9ee`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x18f9940, 0x18fb1d2)`, 7,058 bytes. Before the call it sets the arguments: `mov 0x10(%rsp),%esi` (string pointer), `mov 0x18(%rsp),%rdx` (length), `lea 0x30(%rsp),%rdi` (output pointer); the caller's full behavior and the meaning of those stack slots are not closed here. (The caller FDE also contains its own inlined byte comparisons elsewhere; those are caller-internal logic, not this window, and nothing about them is claimed here.)

### Body behavior: two length tests, two immediates, three tags, no calls

Decoded from the FDE start, the window takes `(out_ptr, s_ptr, len)` in `(rdi, rsi, rdx)` and returns the output pointer in `rax`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x25903d0` | `mov %rdi,%rax` | Output pointer saved (and returned) |
| `0x25903d3` | `cmp $0x9,%rdx` | Length == 9 test |
| `0x25903d7` | `je 0x25903fa` | Length 9 goes to the gas_limit path |
| `0x25903d9` | `cmp $0x5,%rdx` | Length == 5 test |
| `0x25903dd` | `jne 0x2590414` | Other lengths go to tag 2 |
| `0x25903df` | `mov $0x75706e69,%ecx` | "inpu" as a little-endian u32 |
| `0x25903e4` | `xor (%rsi),%ecx` | First 4 bytes xored against "inpu" |
| `0x25903e6` | `movzbl 0x4(%rsi),%edx` | Fifth byte loaded |
| `0x25903ea` | `xor $0x74,%edx` | Fifth byte xored against 't' |
| `0x25903ed` | `or %ecx,%edx` | Either mismatch sets the flag |
| `0x25903ef` | `jne 0x2590414` | Mismatch goes to tag 2 |
| `0x25903f1` | `xor %ecx,%ecx` | Tag 0 |
| `0x25903f3` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x25903f6` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x25903f9` | `ret` | |
| `0x25903fa` | `movabs $0x696d696c5f736167,%rcx` | "gas_limi" as a little-endian u64 |
| `0x2590404` | `xor (%rsi),%rcx` | First 8 bytes xored against "gas_limi" |
| `0x2590407` | `movzbl 0x8(%rsi),%edx` | Ninth byte loaded |
| `0x259040b` | `xor $0x74,%rdx` | Ninth byte xored against 't' |
| `0x259040f` | `or %rcx,%rdx` | Either mismatch sets the flag |
| `0x2590412` | `je 0x259041d` | Full match goes to tag 1 |
| `0x2590414` | `mov $0x2,%cl` | Tag 2 |
| `0x2590416` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x2590419` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x259041c` | `ret` | |
| `0x259041d` | `mov $0x1,%cl` | Tag 1 |
| `0x259041f` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x2590422` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x2590425` | `ret` | |

The window opens directly with the first move — no `endbr64` (an observation, not a scout deviation). Every store path writes byte 0 = 9 and byte 1 = the tag, so the output shape is fully determined: `(9, 0)` for `input`, `(9, 1)` for `gas_limit`, `(9, 2)` for everything else. No length other than 5 or 9 reaches a comparison, so a 5-byte non-`input` string and a 9-byte non-`gas_limit` string both land on tag 2 without reading beyond their own length's comparison bytes.

### Scout notes

No scout correction was needed: every scouted element verified exactly (FDE range, 86-byte body, both keywords, one caller, no naming relocation). One scout precision note, not a behavior correction: the scout listed the caller FDE end as `0x18fb1e0`; the exact end from `--dwarf=frames` is `0x18fb1d2` (the scout end appears to be the following FDE start, the same pattern seen in packets #50/#51/#53/#55). The checker locks the exact end.

## Inferences

- The "keyword classifier" label is an inference from the length-plus-immediate comparison shape shared with packets #15/#25; it is not a source-level name.
- The two output bytes are described as (9, tag) only because every store path writes them that way; what 9 or the tags mean to any caller is unknown.
- The caller passes a string pointer, a length, and an output pointer in the standard positions; what the caller does with the two output bytes is not closed here.

## Unknowns

- The meaning of the leading byte 9 and of tags 0/1/2.
- Whether any other caller reaches this window indirectly (the byte-pattern scan is not a complete xref census).
- The source-level function, type, or component this window belongs to beyond the foundation task framing.

## Limits

- No stdlib type, source-level function, keyword meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
