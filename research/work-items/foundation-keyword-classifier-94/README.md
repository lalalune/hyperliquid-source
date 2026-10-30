# foundation-keyword-classifier-94: what does the until/required_matches window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 84-byte FDE window, its twelve int3 padding bytes, the 16-byte keyword constant it compares against, one incoming direct call with argument setup, and the exact three-tag output rule.
- Excluded: the meaning of the leading output byte 9 and of the tags 0/1/2, the caller's behavior beyond its call site and argument setup, other keyword or string helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two length tests, two comparands readable in full, and three exhaustive output paths with no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1437b90`, no open pull request title mentions it or keyword-classifier, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, or drop-thunk packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_keyword_classifier.py --check research/work-items/foundation-keyword-classifier-94/evidence.json
python3 -m unittest tests.test_foundation_keyword_classifier -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1437b90 --stop-address=0x1437bf0 artifacts/node/94/hl-node
objdump -d --start-address=0x13ba490 --stop-address=0x13ba4d0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site region of the caller FDE window (argument setup, call, and following bytes); the full caller FDE is `[0x13b9560, 0x13baf1a)`, 6586 bytes, and only that region is claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x95ac`, and the caller FDE at `0x2e4210`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x95ac` describes `[0x1437b90, 0x1437be4)`, 84 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x1437be3` is inside the FDE).
- The unwind index stride to the next entry is 96 bytes, ending at `0x1437bf0`, only because twelve `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those twelve padding bytes, and the checker locks the 84-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x1437b90`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x13ba4c6`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x13b9560, 0x13baf1a)`, 6586 bytes. Before the call it sets the arguments: `mov 0xd8(%rsp),%rsi` (string pointer), `mov 0xe0(%rsp),%rdx` (length), `lea 0x70(%rsp),%rdi` (output pointer); the caller's full behavior and the meaning of those stack slots are not closed here.

### Body behavior: two length tests, two comparands, three tags, no calls

Decoded from the FDE start, the window takes `(out_ptr, s_ptr, len)` in `(rdi, rsi, rdx)`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1437b90` | `mov %rdi,%rax` | Output pointer saved |
| `0x1437b93` | `cmp $0x10,%rdx` | Length == 16 test |
| `0x1437b97` | `je 0x1437bba` | Length 16 goes to the 16-byte path |
| `0x1437b99` | `cmp $0x5,%rdx` | Length == 5 test |
| `0x1437b9d` | `jne 0x1437bd2` | Other lengths go to tag 2 |
| `0x1437b9f` | `mov $0x69746e75,%ecx` | "unti" as a little-endian u32 |
| `0x1437ba4` | `xor (%rsi),%ecx` | First 4 bytes xored against "unti" |
| `0x1437ba6` | `movzbl 0x4(%rsi),%edx` | Fifth byte loaded |
| `0x1437baa` | `xor $0x6c,%edx` | Fifth byte xored against 'l' |
| `0x1437bad` | `or %ecx,%edx` | Either mismatch sets the flag |
| `0x1437baf` | `jne 0x1437bd2` | Mismatch goes to tag 2 |
| `0x1437bb1` | `xor %ecx,%ecx` | Tag 0 |
| `0x1437bb3` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1437bb6` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1437bb9` | `ret` | |
| `0x1437bba` | `movdqu (%rsi),%xmm0` | 16 bytes loaded |
| `0x1437bbe` | `pcmpeqb 0x204b10(%rip),%xmm0` | Compared against the constant |
| `0x1437bc6` | `pmovmskb %xmm0,%ecx` | Match mask |
| `0x1437bca` | `cmp $0xffff,%ecx` | All 16 bytes must match |
| `0x1437bd0` | `je 0x1437bdb` | Full match goes to tag 1 |
| `0x1437bd2` | `mov $0x2,%cl` | Tag 2 |
| `0x1437bd4` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1437bd7` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1437bda` | `ret` | |
| `0x1437bdb` | `mov $0x1,%cl` | Tag 1 |
| `0x1437bdd` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1437be0` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1437be3` | `ret` | |

The output rule, in full:

- Tag 0 if and only if length is 5 and the string is exactly `until`: the first 4 bytes xor `0x69746e75` (the little-endian u32 for "unti") is 0 and byte 4 xor `0x6c` ('l') is 0.
- Tag 1 if and only if length is 16 and the 16 bytes equal the constant at `0x204b10`, which reads exactly `required_matches` (verified from the target's own bytes, not assumed from the string table).
- Tag 2 for every other input, including length 5 that is not `until` and length 16 that is not `required_matches`.
- In all three paths byte 0 of the output is 9 and byte 1 is the tag, then `ret`. The window contains no calls, no slots to resolve, and no other side effects.

Note the branch order: length 16 is tested first, then length 5, then the tag-2 fall-through; the 16-byte path itself falls through to tag 2 on mismatch. Length is compared as a 64-bit value (`rdx`); no truncation to a smaller width appears in the window.

Checked edges from the decoded rule:

| Input | Tag |
| --- | --- |
| `until` | 0 |
| `required_matches` | 1 |
| empty | 2 |
| `untilx` (length 6) | 2 |
| `untix` (length 5, not `until`) | 2 |
| `required_matchex` (length 17) | 2 |
| `REQUIRED_MATCHES` (length 16, wrong case) | 2 |
| `required_match` (length 14) | 2 |

### The comparand

The 16-byte comparand is reached through a RIP-relative `pcmpeqb` whose displacement resolves to `0x204b10`. The bytes there read exactly `required_matches`. No other constant, table, or string is read by this window.

## Inferences and unknowns

- **Inferred:** this is a keyword classifier for two keywords (`until`, `required_matches`) with an other-bucket tag. The exact two-keyword shape, the exhaustive three-path structure, and the uniform two-byte output support that label. The binary has no recovered symbol name here. Neither the source-level function name, the meaning of the leading byte 9, the meaning of the tags, nor the caller's purpose for the classification is proven.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The output buffer's layout beyond its first two bytes is not written by this window and is not claimed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, padding bytes, or keyword constant;
- changed FDE extent, padding, or relative relocation target;
- changed caller call bytes or argument setup, and an additional direct-call pattern;
- an unexpected relocation slot mapping to the window;
- changed tag stores or branch displacements.

**No progress gate requested.** Foundation's gates and generated progress files are unchanged. The denominator here is one bounded window, not all string helpers. Next question: establish what the caller does with the (9, tag) output pair, and whether the two keywords belong to one parser or two.
