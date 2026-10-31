# foundation-xor-mixer-94: what does the multiply/xor mixer window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 73-byte FDE window, its seven int3 padding bytes, the seed RELATIVE relocation slot, the single incoming direct call with its caller FDE, and the exact multiply/xor rule.
- Excluded: the seed's runtime values and meaning, the result's meaning, the caller's behavior beyond its call site and result use, other mixer windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: three 128-bit multiplies interleaved with xors against a relocated seed, no calls, no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4b27620`, no open pull request title mentions it or xor-mixer, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, or half-swap packets.

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_xor_mixer.py --check research/work-items/foundation-xor-mixer-94/evidence.json
python3 -m unittest tests.test_foundation_xor_mixer -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4b27620 --stop-address=0x4b27670 artifacts/node/94/hl-node
objdump -d --start-address=0x4dd6ea0 --stop-address=0x4dd7694 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains only the call-site region of the caller FDE (prologue through call); the full caller FDE is `[0x4dd6ea0, 0x4dd839e)`, and only that region is claimed here. The `frames.txt` file retains excerpts selecting the window CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2564fc`, the next FDE at `0x256510`, the caller CIE at `0x2dc714`, and the caller FDE at `0x6088f4`. The checker locks these raw FDE/CIE records and their PC/range fields (initial_location is a 4-byte signed PC-relative value under the zR/zPLR encodings; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2564fc` describes `[0x4b27620, 0x4b27669)`, 73 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x4b27668` is inside the FDE).
- The unwind index stride to the next entry is 80 bytes, ending at `0x4b27670`, only because seven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those seven padding bytes, and the checker locks the 73-byte body and the padding separately. The next FDE starts exactly at `0x4b27670`.
- The window starts directly with a `mov`; there is no `endbr64` landing pad.
- No relocation of any type in `.rela.dyn` maps a slot to `0x4b27620`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: seed xors and three 128-bit multiplies, no calls, no branches

Decoded from the FDE start, the window takes two input pointers, `rdi` (in0, 8 bytes read at offset 0) and `rsi` (in1, 20 bytes read at offsets 0, 4, 8, 12):

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4b27620` | `mov 0xc46db9(%rip),%rdx` | Load seed pointer from slot `0x576e3e0` |
| `0x4b27627` | `mov (%rdx),%r10` | seed0 = seed[0] |
| `0x4b2762a` | `mov 0xc(%rsi),%r8` | in1[12] |
| `0x4b2762e` | `xor %r10,%r8` | D = in1[12] ^ seed0 |
| `0x4b27631` | `mov (%rsi),%rcx` | in1[0] |
| `0x4b27634` | `mov 0x8(%rsi),%rax` | in1[8] |
| `0x4b27638` | `xor 0x8(%rdx),%rax` | C = in1[8] ^ seed[8] |
| `0x4b2763c` | `mul %r8` | t1 = C * D, 128-bit in rdx:rax |
| `0x4b2763f` | `mov %rax,%r8` | t1lo |
| `0x4b27642` | `mov %rdx,%r9` | t1hi |
| `0x4b27645` | `mov 0x4(%rsi),%rdx` | in1[4] |
| `0x4b27649` | `xor %r10,%rdx` | B = in1[4] ^ seed0 |
| `0x4b2764c` | `xor (%rdi),%rcx` | A = in1[0] ^ in0[0] |
| `0x4b2764f` | `mov %rcx,%rax` | A |
| `0x4b27652` | `mul %rdx` | t2 = A * B, 128-bit in rdx:rax |
| `0x4b27655` | `xor %rdx,%r9` | r9 = t1hi ^ t2hi |
| `0x4b27658` | `xor %r8,%r9` | r9 = t1hi ^ t2hi ^ t1lo |
| `0x4b2765b` | `xor %r9,%rax` | rax = t2lo ^ t1hi ^ t2hi ^ t1lo |
| `0x4b2765e` | `xor $0x14,%rax` | acc = t2lo ^ t2hi ^ t1lo ^ 0x14 |
| `0x4b27662` | `mul %r10` | t3 = acc * seed0, 128-bit in rdx:rax |
| `0x4b27665` | `xor %rdx,%rax` | return t3lo ^ t3hi |
| `0x4b27668` | `ret` | |

The rule, in full:

- Let seed0 = seed[0] and seed8 = seed[8], where seed is the pointer loaded from slot `0x576e3e0`.
- D = in1[12] ^ seed0; C = in1[8] ^ seed8; t1 = C * D (128-bit).
- B = in1[4] ^ seed0; A = in1[0] ^ in0[0]; t2 = A * B (128-bit).
- acc = t2lo ^ t2hi ^ t1lo ^ t1hi ^ 0x14. The fold order matters: r9 first holds t1hi (moved from rdx after the first mul), then xors t2hi, then t1lo; rax (t2lo) xors r9 and 0x14. So all four product halves enter acc.
- t3 = acc * seed0 (128-bit); return t3lo ^ t3hi in rax.
- `rax` is the only written return register; `r8`–`r11` are caller-saved scratch.

Checked edges from the decoded rule (restatement, not execution):

- Zero inputs and zero seeds → 0 (every xor is 0, every product is 0, acc = 0x14, t3 = 0x14 * 0 = 0).
- Sample: in0 = bytes 0..7, in1 = bytes 0..19, seed0 = 0xdeadbeefcafef00d, seed8 = 0x123456789abcdef0 → 0x9c4e42a7cec11b69.
- Zero seed0 → 0 regardless of seed8 (t3 = acc * 0 = 0).
- Unit seed0 with zero inputs → 0x14 (acc = 0x14, t3 = 0x14, fold 0x14 ^ 0).

### Seed slot: relocated, values unknown

- Slot `0x576e3e0` carries one `R_X86_64_RELATIVE` record with addend `0x5788348`. The addend is the seed struct's runtime address, not a file value: the file stores 0 at that slot, applied only at load time. The checker locks the slot address, the RELATIVE type, and the addend — not any seed value.
- The seed pointer is dereferenced twice (seed[0] and seed[8]); no other seed word is read.
- The addend sits just inside `.bss` (`[0x5788300, 0x59b0e80)`), 0x48 past its start — consistent with a runtime seed struct, though its contents and meaning are not claimed.

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start |
| --- | --- | --- |
| `0x4dd768f` | `[0x4dd6ea0, 0x4dd839e)` | Yes, linear disassembly from FDE start |

The call site's 5-byte `e8` + rel32 sequence is locked by the checker, and its target resolves exactly to `0x4b27620`. The caller's argument setup, as retained in `caller.objdump.txt`, is `lea 0x20(%r13),%rdi` immediately before the call (in0 = r13 + 0x20); `rsi` is the caller's incoming second argument, spilled to the stack (`mov %rsi,0x8(%rsp)`) just before the call. After the call the caller moves rax to rsi and shifts right by 0x39; the caller's purpose is not claimed.

### Scout corrections (two)

1. **t1hi IS folded into acc.** The scout note described the accumulator as `acc = t2lo ^ t2hi ^ t1lo ^ 0x14`, omitting t1hi. The retained bytes show otherwise: after the first mul, `mov %rdx,%r9` saves t1hi in r9; the fold sequence then xors t2hi and t1lo into r9, and `xor %r9,%rax` folds all of r9 — including t1hi — into t2lo before the 0x14 xor. So acc = t2lo ^ t2hi ^ t1lo ^ t1hi ^ 0x14. The difference is real, not notational: on the sample edge the scout's formula gives 0x168f9edeb5fcf46a while the retained bytes give 0x9c4e42a7cec11b69, because t1hi is nonzero there. The checker and unit test lock the corrected form, and the test explicitly asserts the scout's value does NOT match.

2. **Seed addend is 0x5788348, not 0x5852bc.** The scout note gave the seed slot's RELATIVE addend as 0x5852bc. The retained `.rela.dyn` record for slot `0x576e3e0` (confirmed both by direct section parse and by readelf, which prints the addend in hex without a prefix) says 0x5788348. The corrected value sits just inside `.bss`, while 0x5852bc is not a valid address in this binary's loaded segments at all. The checker locks 0x5788348.

Everything else in the scout note verified exactly: FDE range, padding count, seed slot address, the multiply/xor chain shape including the 0x14 constant, and the single caller.

## Inferences

- The "multiply/xor mixer" label is an inference from the three-multiply, seed-xor shape. It is kept separate from the observed arithmetic rule.
- The result's meaning (hash, checksum, tag, or anything else) is unknown and is not inferred from the shape.

## Unknowns

- The seed's runtime values and meaning, and what kind of quantities the inputs are.
- The window's source-level name, type, and component owner.
- The caller's purpose beyond its call site, argument setup, and result use.
- Whether any other caller reaches the window indirectly (the scan is not a complete xref census).

## Limits

- No source-level function, type, or value meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
