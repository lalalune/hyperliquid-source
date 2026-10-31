# foundation-slot-move-kind-gated-restore-94: what does the slot-move window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 98-byte FDE window with fourteen padding bytes, the slot-move rule with its kind-gated restore and tag byte 5, the exact incoming-call scan result (zero direct sites), and the 30-slot relocation list.
- Excluded: what the kind values mean, what the slot holds, who reads the tag byte, any wider slot-move family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a slot move that always overwrites a link field, zeroes a 16-byte slot, then restores it conditionally by a kind byte while tagging 5. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x3290130`, no open pull request title mentions it or slot-move-kind-gated-restore, and its bytes overlap nothing in packets #1–#85.

## Scout note — with one material correction

The round-13 scout note listed this window (ranked #4) with FDE `[0x3290130, 0x3290192)`, 98 bytes, 14 padding bytes, zero direct callers, 30 R_X86_64_RELATIVE slots, and nearest claimed window byte-range select `0x359be70` (packet #26) `0x30bd40` away. Every one of those numbers verified exactly, including the full body, the zero incoming sites, and all 30 slot addresses in scout order.

**Correction to the scout's restore mapping, found by re-deriving both branches from the bytes:** the scout summarized the restore as "full restore iff kind ≤ 4, else first-qword-only restore", and noted kind in `[0x10..0x15]` "takes the same path" as kind > `0x15`. That is wrong. The actual band structure, locked by the checker, is:

- kind ≤ 4 → full 16-byte restore;
- kind in `[16..21]` (`0x10..0x15`) → first-qword-only restore;
- kind in `[5..15]` or `[22..255]` → **no restore at all** (the slot stays zeroed).

The scout's error was conflating the fall-through first-qword path (reachable only when `(kind − 16) mod 2^32 < 6`, i.e. kind in `[16..21]`) with the tag-only path reached from the second branch for kind > 4. The derivation below shows both branches step by step; the checker locks both branch displacements and all eight band edges. Nothing else in the scout note needed correction.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_slot_move_kind_gated_restore.py --check research/work-items/foundation-slot-move-kind-gated-restore-94/evidence.json
python3 -m unittest tests.test_foundation_slot_move_kind_gated_restore -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3290130 --stop-address=0x32901a0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its fourteen padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x1064dc` (this window) and `0x47ced8` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1064dc` describes `[0x3290130, 0x3290192)`, 98 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fourteen `int3` bytes follow: the next FDE starts exactly at `0x32901a0` (record at `.eh_frame+0x47ced8`, range to `0x3290217`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does NOT open with `endbr64` (an observation, not a scout deviation); its first instruction is `mov %rdi,%rax`.
- GNU objdump prints this window under a nearest-symbol label with a `0x1d17cd0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: slot move with kind-gated restore and tag 5, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | 48 89 f8 | mov %rdi,%rax |
| 0x03 | 4c 8b 82 d8 00 00 00 | mov 0xd8(%rdx),%r8 |
| 0x0a | 45 31 c9 | xor %r9d,%r9d |
| 0x0d | 48 83 39 00 | cmpq $0x0,(%rcx) |
| 0x11 | 41 0f 94 c1 | sete %r9b |
| 0x15 | 41 c1 e1 04 | shl $0x4,%r9d |
| 0x19 | 42 0f b6 74 09 40 | movzbl 0x40(%rcx,%r9,1),%esi |
| 0x1f | 4a 8d 14 09 | lea (%rcx,%r9,1),%rdx |
| 0x23 | 48 83 c2 30 | add $0x30,%rdx |
| 0x27 | 42 0f 10 44 09 30 | movups 0x30(%rcx,%r9,1),%xmm0 |
| 0x2d | 4a 8b 7c 09 30 | mov 0x30(%rcx,%r9,1),%rdi |
| 0x32 | 4d 8b 80 38 02 00 00 | mov 0x238(%r8),%r8 |
| 0x39 | 4e 89 44 09 28 | mov %r8,0x28(%rcx,%r9,1) |
| 0x3e | 0f 57 c9 | xorps %xmm1,%xmm1 |
| 0x41 | 42 0f 11 4c 09 30 | movups %xmm1,0x30(%rcx,%r9,1) |
| 0x47 | 8d 4e f0 | lea -0x10(%rsi),%ecx |
| 0x4a | 83 f9 06 | cmp $0x6,%ecx |
| 0x4d | 73 07 | jae 0x3290186 |
| 0x4f | 48 89 3a | mov %rdi,(%rdx) |
| 0x52 | c6 00 05 | movb $0x5,(%rax) |
| 0x55 | c3 | ret |
| 0x56 | 83 fe 04 | cmp $0x4,%esi |
| 0x59 | 77 f7 | ja 0x3290182 |
| 0x5b | 0f 11 02 | movups %xmm0,(%rdx) |
| 0x5e | c6 00 05 | movb $0x5,(%rax) |
| 0x61 | c3 | ret |

Rule, derived step by step. The slot selector is `r9 = ([rcx] == 0) ? 16 : 0` (`sete` after comparing `[rcx]` against zero, then `shl $4`). The kind byte is `[rcx + r9 + 0x40]`, and the slot base is `rcx + r9 + 0x30`. The saved 16 bytes at the slot base go to `xmm0`, and the first qword goes to `rdi`. The link field `[rcx + r9 + 0x28]` is then overwritten with the two-hop value `[[rdx-input + 0xd8] + 0x238]` — the first hop reads from the *input* `rdx` (second argument) before `rdx` is overwritten by the `lea`, so the two `rdx` uses must not be confused. The slot is then zeroed.

The restore bands follow from the two branches, both unsigned:

- First branch: `ecx = (kind − 16) mod 2^32`; `jae` is taken unless `ecx < 6`. That fall-through happens exactly for kind in `[16..21]`, where the first qword is restored from `rdi` and the tag is stored.
- Second branch (reached for kind in `[0..15]` or `[22..255]`): `cmp $0x4,%esi; ja` jumps to the tag-only path for kind > 4, so kinds `[5..15]` and `[22..255]` restore nothing. Only kind ≤ 4 falls through to the full 16-byte restore from `xmm0`.

On all three paths the output byte `[rax]` is set to 5, where `rax` is the original `rdi` saved by the first instruction. No return-value contract is claimed: `rax` holds the output pointer at every `ret`, not a computed result.

No call opcode appears inside the window. The only control flow is the two forward conditional branches above.

### Take-helper adjacency, stated head-on

Packet #9's take helpers also move a slot and tag an output, so the resemblance is real and is not hidden. This window is nonetheless a separate binding: #9's helpers have no kind byte, no kind-gated restore with three bands, no link-field overwrite from a two-hop pointer load, and no zero-then-conditional-restore structure. The kind gate and the link overwrite are the distinguishing elements, and both are locked exactly from this window's own bytes. No shared primitive is claimed and no census is built.

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: 30 RELATIVE slots, reported as a list

Thirty `R_X86_64_RELATIVE` records in `.rela.dyn` name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). They are a pointer table; the checker locks all 30 slot addresses in scan order and the evidence lists them verbatim:

`0x56e3b70`, `0x56e3d80`, `0x56e4230`, `0x56e4380`, `0x56e46e0`, `0x56e4830`, `0x56e4980`, `0x56e4c20`, `0x56e4d70`, `0x56e4ec0`, `0x56e5010`, `0x56e5160`, `0x56e52b0`, `0x56e5550`, `0x56e56a0`, `0x56e57f0`, `0x56e5940`, `0x56e5d30`, `0x56e5e80`, `0x56e6120`, `0x56e63c0`, `0x56e6510`, `0x56e6660`, `0x56e67b0`, `0x56e6900`, `0x56e6a50`, `0x56e6cf0`, `0x56e6f90`, `0x56e7230`, `0x56e7380`.

No meaning is claimed for the table they belong to, and the slot list does not identify the window's provenance.

## Inferences

- The "slot move with kind-gated restore" label is an inference from the observed rule: a 16-byte slot is moved aside, zeroed, and conditionally restored by kind. It is kept separate from the rule itself.
- The `[rcx + r9 + 0x28]` field is plausibly a link field and the `[rdi]` byte plausibly a tag, but their owning types are unknown and not claimed.
- The 30-slot pointer table suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the kind values 0–4, 16–21, and the rest mean, and what reads the slot or the tag byte.
- Whether the window is reached via the pointer table, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot list does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
