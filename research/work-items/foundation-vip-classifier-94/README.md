# foundation-vip-classifier-94: what does the mm/vip window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 70-byte FDE window, its ten int3 padding bytes, one incoming direct call with argument setup, and the exact three-tag output rule.
- Excluded: the meaning of the leading output byte 9 and of the tags 0/1/2, the caller's behavior beyond its call site and argument setup, other keyword or string helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two length tests, two comparands readable in full, and three exhaustive output paths with no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1e6d560`, no open pull request title mentions it or vip-classifier, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, or dual-table-lookup packets.

This window is bound **alone**. It shares packet #15's two-byte output shape (byte 0 = 9, byte 1 = tag) but is a different window with different strings (`mm` / `vip` here, `until` / `required_matches` there) and a different tag mapping (here `vip` → 0 and `mm` → 1; there `until` → 0 and `required_matches` → 1). It is never presented as part of a classifier family, and no census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_vip_classifier.py --check research/work-items/foundation-vip-classifier-94/evidence.json
python3 -m unittest tests.test_foundation_vip_classifier -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1e6d560 --stop-address=0x1e6d5b0 artifacts/node/94/hl-node
objdump -d --start-address=0x171c688 --stop-address=0x171c69c artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site region of the caller FDE window (argument setup and call); the full caller FDE is `[0x171b780, 0x171d0fd)`, 7037 bytes, and only that region is claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x3cdc0`, and the caller FDE at `0x325444` (whose CIE sits at section offset `0x2dc714`, augmentation `zPLR`). The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x3cdc0` describes `[0x1e6d560, 0x1e6d5a6)`, 70 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x1e6d5a5` is inside the FDE).
- The unwind index stride to the next entry is 80 bytes, ending at `0x1e6d5b0`, only because ten `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those ten padding bytes, and the checker locks the 70-byte body and the padding separately. The next FDE starts exactly at `0x1e6d5b0`.
- No relocation of any type in `.rela.dyn` maps a slot to `0x1e6d560`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x171c697`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x171b780, 0x171d0fd)`, 7037 bytes. Before the call it sets the arguments: `mov 0x38(%rsp),%rsi` (string pointer), `mov 0x40(%rsp),%rdx` (length), `lea 0x10(%rsp),%rdi` (output pointer); the caller's full behavior and the meaning of those stack slots are not closed here.

### Body behavior: two length tests, two comparands, three tags, no calls

Decoded from the FDE start, the window takes `(out_ptr, s_ptr, len)` in `(rdi, rsi, rdx)`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1e6d560` | `mov %rdi,%rax` | Output pointer saved (and returned) |
| `0x1e6d563` | `cmp $0x2,%rdx` | Length == 2 test |
| `0x1e6d567` | `je 0x1e6d58d` | Length 2 goes to the mm path |
| `0x1e6d569` | `cmp $0x3,%rdx` | Length == 3 test |
| `0x1e6d56d` | `jne 0x1e6d594` | Other lengths go to tag 2 |
| `0x1e6d56f` | `movzwl (%rsi),%ecx` | First 2 bytes loaded |
| `0x1e6d572` | `xor $0x6976,%ecx` | First 2 bytes xored against "vi" |
| `0x1e6d578` | `movzbl 0x2(%rsi),%edx` | Third byte loaded |
| `0x1e6d57c` | `xor $0x70,%edx` | Third byte xored against 'p' |
| `0x1e6d57f` | `or %cx,%dx` | Either mismatch sets the flag |
| `0x1e6d582` | `jne 0x1e6d594` | Mismatch goes to tag 2 |
| `0x1e6d584` | `xor %ecx,%ecx` | Tag 0 |
| `0x1e6d586` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1e6d589` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1e6d58c` | `ret` | |
| `0x1e6d58d` | `cmpw $0x6d6d,(%rsi)` | 2 bytes compared against "mm" |
| `0x1e6d592` | `je 0x1e6d59d` | Full match goes to tag 1 |
| `0x1e6d594` | `mov $0x2,%cl` | Tag 2 |
| `0x1e6d596` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1e6d599` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1e6d59c` | `ret` | |
| `0x1e6d59d` | `mov $0x1,%cl` | Tag 1 |
| `0x1e6d59f` | `mov %cl,0x1(%rax)` | Byte 1 = tag |
| `0x1e6d5a2` | `movb $0x9,(%rax)` | Byte 0 = 9 |
| `0x1e6d5a5` | `ret` | |

The output rule, in full:

- Tag 0 if and only if length is 3 and the string is exactly `vip`: the first 2 bytes xor `0x6976` (the little-endian u16 for "vi") is 0 and byte 2 xor `0x70` ('p') is 0.
- Tag 1 if and only if length is 2 and the 2 bytes equal `0x6d6d` (the little-endian u16 for "mm").
- Tag 2 for every other input, including length 2 that is not `mm` and length 3 that is not `vip`.
- In all three paths byte 0 of the output is 9 and byte 1 is the tag, then `ret`. The window contains no calls, no slots to resolve, and no other side effects. `rax` returns the output pointer.

Note the branch order: length 2 is tested first, then length 3, then the tag-2 fall-through; the length-2 path itself falls through to tag 2 on mismatch, and the length-3 path falls through to tag 2 on mismatch. Length is compared as a 64-bit value (`rdx`); no truncation to a smaller width appears in the window. The length-2 path reads exactly 2 bytes and the length-3 path reads exactly 3 bytes; other lengths read nothing.

Checked edges from the decoded rule:

| Input | Tag |
| --- | --- |
| `vip` | 0 |
| `mm` | 1 |
| empty | 2 |
| `m` (length 1) | 2 |
| `vi` (length 2, not `mm`) | 2 |
| `mmx` (length 3, not `vip`) | 2 |
| `vix` (length 3, third byte not 'p') | 2 |
| `vipx` (length 4) | 2 |
| `MM` (wrong case) | 2 |

## Inferences and unknowns

- **Inferred:** this is a keyword classifier for two keywords (`vip`, `mm`) with an other-bucket tag. The exact two-keyword shape, the exhaustive three-path structure, and the uniform two-byte output support that label. The binary has no recovered symbol name here. Neither the source-level function name, the meaning of the leading byte 9, the meaning of the tags, nor the caller's purpose for the classification is proven.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The output buffer's layout beyond its first two bytes is not written by this window and is not claimed.
- No scout correction was needed: every scouted element (FDE range, padding count, both comparands, branch targets, the single caller) verified exactly from the bytes.
