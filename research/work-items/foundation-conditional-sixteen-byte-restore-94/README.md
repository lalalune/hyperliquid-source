# foundation-conditional-sixteen-byte-restore-94: what does the conditional 16-byte restore window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 98-byte FDE window with fourteen padding bytes, the conditional 16-byte restore rule with its exact field offsets and thresholds, the exact incoming-call scan result (zero direct sites), and the single naming relocation slot.
- Excluded: what the node fields mean, what the block and restored values represent, any wider restore family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a block selected by a null test, saved and zeroed, then conditionally restored in whole, in part, or not at all based on a gate byte, with a constant byte stored on every path. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4e6cf10`, no open pull request title mentions it or conditional-sixteen-byte-restore, and its bytes overlap nothing in packets #1–#101.

## Scout note

The round-15 scout note listed this window (backup B2, the last round-15 item after the ranked four and backup B1) with FDE `[0x4e6cf10, 0x4e6cf72)`, 98 bytes, 14 padding bytes, zero direct callers, one naming relocation slot (`0x574bcf8`), and nearest claimed window byte-indexed dual qword load `0x4e48600` (packet #63) `0x24910` away. Every element verified exactly; no scout correction was needed.

## Component-adjacent caveat

This is the heaviest backup of round 15, and its rule is plainly one step inside a larger state-manipulation routine: the window reads a leading qword, a two-hop value, and a gate byte, and it rewrites a neighboring block. What is claimed here is deliberately narrow — the exact behavior of this one FDE window, locked byte by byte, with its own data edges. No claim is made about the surrounding routine, the meaning of the block or its fields, or what consumes the restored values. The window is self-contained in the only sense the packet pattern requires: a complete FDE, no calls inside, no branch leaving it, and a return on every path. If a reviewer finds the window too routine-adjacent to stand alone, that is a scoping judgment, not a defect in the locked bytes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_conditional_sixteen_byte_restore.py --check research/work-items/foundation-conditional-sixteen-byte-restore-94/evidence.json
python3 -m unittest tests.test_foundation_conditional_sixteen_byte_restore -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4e6cf10 --stop-address=0x4e6cf80 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its fourteen padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2788bc` (this window) and `0x2788d0` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2788bc` describes `[0x4e6cf10, 0x4e6cf72)`, 98 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fourteen `int3` bytes follow: the next FDE starts exactly at `0x4e6cf80` (record at `.eh_frame+0x2788d0`, range to `0x4e6cfd4`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does **not** open with `endbr64`: it opens directly with `mov %rdi,%rax`. That is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x4e6cf10`. All arithmetic wraps at 64 bits unless noted; the gate-byte arithmetic is 32-bit.

- Offset `0x00`: `mov %rdi,%rax` — save the entry pointer; it is the target of the final byte store on every path.
- Offset `0x03`: `mov 0xd8(%rdx),%r8` — first hop of the two-hop value load.
- Offset `0x0a`: `xor %r9d,%r9d` — clear the block offset selector.
- Offset `0x0d`: `cmpq $0x0,(%rcx)` — null test on the leading qword of the block struct.
- Offset `0x11`: `sete %r9b` — selector byte becomes 1 exactly when the leading qword is null.
- Offset `0x15`: `shl $0x4,%r9d` — selector becomes 16 on the null path, 0 otherwise.
- Offset `0x19`: `movzbl 0x40(%rcx,%r9,1),%esi` — gate byte at block offset `+0x40`, zero-extended.
- Offset `0x1f`: `lea (%rcx,%r9,1),%rdx` — block base = `rcx + r9` (this overwrites the entry `rdx` argument).
- Offset `0x23`: `add $0x30,%rdx` — `rdx` now points at the 16-byte block at base `+0x30`.
- Offset `0x27`: `movups 0x30(%rcx,%r9,1),%xmm0` — save the 16-byte block.
- Offset `0x2d`: `mov 0x30(%rcx,%r9,1),%rdi` — save the block's first qword (this overwrites the entry `rdi` argument; the original is already in `rax`).
- Offset `0x32`: `mov 0x238(%r8),%r8` — second hop of the two-hop value load.
- Offset `0x39`: `mov %r8,0x28(%rcx,%r9,1)` — store the two-hop value at base `+0x28`.
- Offset `0x3e`: `xorps %xmm1,%xmm1` — zero vector preparation.
- Offset `0x41`: `movups %xmm1,0x30(%rcx,%r9,1)` — zero the 16-byte block.
- Offset `0x47`: `lea -0x10(%rsi),%ecx` — gate byte minus 16, 32-bit wraparound.
- Offset `0x4a`: `cmp $0x6,%ecx` — unsigned threshold test against 7.
- Offset `0x4d`: `jae 0x4e6cf66` (2 bytes, disp `0x07`) — gate bytes outside `0x10..0x16` take the second test.
- Offset `0x4f`: `mov %rdi,(%rdx)` — qword restore: only the first qword of the saved block returns; the second qword stays zeroed.
- Offset `0x52`: `movb $0x5,(%rax)` — byte 5 at the entry pointer.
- Offset `0x55`: `ret` — qword path return.
- Offset `0x56`: `cmp $0x4,%esi` — second threshold test on the gate byte itself.
- Offset `0x59`: `ja 0x4e6cf62` (2 bytes, disp `0xf7` = −9) — gate bytes above 4 skip the restore.
- Offset `0x5b`: `movups %xmm0,(%rdx)` — full restore: the saved 16 bytes return whole.
- Offset `0x5e`: `movb $0x5,(%rax)` — byte 5 at the entry pointer.
- Offset `0x61`: `ret` — full/no-restore path return.

### Decoded rule

Let `base = rcx + (([rcx] == 0) ? 16 : 0)` and `b = byte [base+0x40]` (zero-extended). On every path:

- `[base+0x28] = [[rdx+0xd8]+0x238]`;
- the 16 bytes at `[base+0x30]` are first saved, then zeroed;
- byte `[original rdi] = 5`.

Then, by `b`:

- `b` in `0x10..0x16` (`(b − 0x10)` unsigned below 7): only the first qword of the saved block is restored to `[base+0x30]`; the second qword stays zeroed.
- `b` in `0x00..0x04` (reached only when the first test fails, since bytes below `0x10` wrap): the full saved 16 bytes are restored to `[base+0x30]`.
- Otherwise (`b` in `0x05..0x0f` or above `0x16`): no restore; the block stays zeroed.

No field is written except the three listed stores. The gate byte itself is never written, and the entry `rdx`/`rdi` arguments are overwritten only as scratch after their values are consumed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x574bcf8` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed.

## Inferences

- The "conditional 16-byte restore" label is an inference from the save-zero-conditionally-restore shape; the window itself names nothing.
- The null test on the leading qword selects between two adjacent 16-byte-spaced blocks (offset 0 vs 16), but whether those are two slots, two states, or two structs is not claimed.
- The byte 5 stored at the entry pointer on every path looks like a status or tag write, but its meaning is not claimed.

## Unknowns

- What the block struct, the two-hop value, and the gate byte represent.
- Whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- What the 16-byte block held before the window ran, beyond the bytes the window itself saves.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
