# foundation-length-prefix-encoder-94: what does the 0x55716a0 window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 106-byte FDE window, its six int3 padding bytes, the three-path length-prefix rule with exact header widths, one incoming direct call with argument setup, and the 32-bit truncation edge of the third path.
- Excluded: the meaning of the header constants (1, 5, 0xd and the 8/16 multipliers), the caller's behavior beyond its call site and argument setup, other length-prefix or varint helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two length thresholds, three exhaustive output paths, and no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x55716a0`, no open pull request title mentions it or length-prefix-encoder, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets. Nearest claimed window: the bsr clamp ladder `0x556e980` (packet #49), `0x2d20` away; nothing in `0x55716xx` is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_length_prefix_encoder.py --check research/work-items/foundation-length-prefix-encoder-94/evidence.json
python3 -m unittest tests.test_foundation_length_prefix_encoder -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x55716a0 --stop-address=0x5571710 artifacts/node/94/hl-node
objdump -d --start-address=0x5573e20 --stop-address=0x5573e35 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site region of the caller FDE window (argument setup, call, and following bytes); the full caller FDE is `[0x55739f0, 0x5573f89)`, 1,529 bytes, and only that region is claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2d14c4`, the caller FDE at `0x2d1784`, and the next FDE at `0x2d14d8`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2d14c4` describes `[0x55716a0, 0x557170a)`, 106 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5571709` is inside the FDE).
- The unwind index stride to the next entry is 112 bytes, ending at `0x5571710`, only because six `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those six padding bytes, and the checker locks the 106-byte body and the padding separately.
- No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x5573e2b`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x55739f0, 0x5573f89)`, 1,529 bytes. Before the call it sets the arguments: `mov 0x8(%rsp),%rsi` (payload-byte pointer), `mov %r10,%rdx` (length), `mov %r12,%rdi` (output pointer); the caller's full behavior and the meaning of those registers are not closed here.

### Body behavior: two thresholds, three paths, no calls

Decoded from the FDE start, the window takes `(out_ptr, payload_ptr, length)` in `(rdi, rdx, rcx)` and returns the total length in `eax`. The window opens with `endbr64` (an observation, not a scout deviation). Each path stores a header, then one payload byte at the header's end, then returns. One overlap must be stated exactly: in the third path the payload store at offset 3 overwrites the dword header's top byte, so the observable output there is 4 bytes (header bytes 0–2 plus the payload), not 5 — the dword's top byte is written and then immediately replaced, and only the first three header bytes survive in the output:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x55716a0` | `endbr64` | Landing pad |
| `0x55716a4` | `cmp $0x1f,%rcx` | Length ≤ 0x1f test (unsigned 64-bit) |
| `0x55716a8` | `ja 0x55716c8` | Larger lengths go to the second test |
| `0x55716aa` | `lea 0x1(,%rcx,8),%ecx` | Path 1 header: (length × 8 + 1), 32-bit |
| `0x55716b1` | `mov $0x1,%esi` | Path 1 payload index |
| `0x55716b6` | `mov $0x2,%eax` | Path 1 return: 2 |
| `0x55716bb` | `mov %cl,(%rdi)` | Path 1 header stored as one byte (mod 256) |
| `0x55716bd` | `movzbl (%rdx),%edx` | Payload byte loaded |
| `0x55716c0` | `mov %dl,(%rdi,%rsi,1)` | Payload byte stored at offset 1 |
| `0x55716c3` | `ret` | |
| `0x55716c4` | `nopl 0x0(%rax)` | Gap nop inside the body, locked as a body byte |
| `0x55716c8` | `cmp $0xfff,%rcx` | Length ≤ 0xfff test (unsigned 64-bit) |
| `0x55716cf` | `jbe 0x55716f0` | Smaller lengths go to path 2 |
| `0x55716d1` | `shl $0x4,%ecx` | Path 3 header: length × 16, 32-bit |
| `0x55716d4` | `mov $0x3,%esi` | Path 3 payload index |
| `0x55716d9` | `mov $0x4,%eax` | Path 3 return: 4 |
| `0x55716de` | `add $0xd,%ecx` | Path 3 header addend |
| `0x55716e1` | `mov %ecx,(%rdi)` | Path 3 header stored as one dword (mod 2^32) |
| `0x55716e3` | `movzbl (%rdx),%edx` | Payload byte loaded |
| `0x55716e6` | `mov %dl,(%rdi,%rsi,1)` | Payload byte stored at offset 3 |
| `0x55716e9` | `ret` | |
| `0x55716ea` | `nopw 0x0(%rax,%rax,1)` | Gap nop inside the body, locked as a body byte |
| `0x55716f0` | `shl $0x4,%ecx` | Path 2 header: length × 16, 32-bit |
| `0x55716f3` | `mov $0x2,%esi` | Path 2 payload index |
| `0x55716f8` | `mov $0x3,%eax` | Path 2 return: 3 |
| `0x55716fd` | `add $0x5,%ecx` | Path 2 header addend |
| `0x5571700` | `mov %cx,(%rdi)` | Path 2 header stored as one word (mod 65536) |
| `0x5571703` | `movzbl (%rdx),%edx` | Payload byte loaded |
| `0x5571706` | `mov %dl,(%rdi,%rsi,1)` | Payload byte stored at offset 2 |
| `0x5571709` | `ret` | |

Rule, stated exactly:

- length ≤ 0x1f: byte `[rdi]` = (length × 8 + 1) mod 256, byte `[rdi + 1]` = byte `[rdx]`, return 2.
- length ≤ 0xfff: word `[rdi]` = (length × 16 + 5) mod 65536, little-endian, byte `[rdi + 2]` = byte `[rdx]`, return 3.
- else: dword `[rdi]` = ((length mod 2^32) × 16 + 13) mod 2^32, little-endian, byte `[rdi + 3]` = byte `[rdx]`, return 4.

Header widths, stated exactly: the first path's header uses 8-bit `cl`, the second 16-bit `cx`, the third 32-bit `ecx`. The third path is the only one that truncates: its `shl` operates on 32-bit `ecx`, so a length above 2^32 is reduced mod 2^32 before the multiply — for example length `0x100000001` encodes header dword `0x0000001d`, and length `0xffffffff` encodes header dword `0xfffffffd` (observable output `fd ff ff` plus the payload byte, since the payload overwrites the dword's top byte). The first two paths take the full 64-bit length, but their thresholds (0x1f, 0xfff) keep the products small, so no truncation is observable there. The payload is a single byte in every path; no longer payload is claimed, and no meaning is claimed for the header constants or multipliers.

## Inferences

- The "length-prefix encoder" label is an inference from the three-path shape (a length-dependent header followed by one payload byte). It is kept separate from the observed rule above.
- The caller registers are described only as argument setup; the caller's purpose and the meaning of its length value are not inferred.

## Unknowns

- The meaning of the header constants (1, 5, 0xd) and the multipliers (8, 16).
- Whether the output buffer is caller-owned or reused; the window only writes and returns a length.
- The source-level function, its argument types, and its stdlib or private provenance. The nearest preceding `ctype` `do_widen` symbol annotation in objdump output is far below this window and proves nothing about provenance; no claim is made either way.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
