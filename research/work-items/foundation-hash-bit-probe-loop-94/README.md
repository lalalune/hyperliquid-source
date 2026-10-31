# foundation-hash-bit-probe-loop-94: what does the hash bit-probe window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 131-byte FDE window with thirteen padding bytes, the hash bit-probe rule it implements, the exact incoming-call scan result (zero direct sites), and the one relocation slot naming the window.
- Excluded: the meaning of the struct fields, the contents or purpose of the probed table, the identity or purpose of any caller (none found by the direct-call scan), and any wider hash-filter family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a loop that hashes a key, probes one bit per round from a 64-byte table block, and returns 1 exactly when every probed bit is set. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window is heavier than the recent single-gate packets (a loop, a multiply-based block offset, a hash recurrence), and that weight is stated head-on rather than buried: it is bound because the rule locks exactly from its own bytes — every instruction at a fixed offset, every branch target on a retained instruction start, zero direct call sites, one naming slot — not because it is small. No caller context is needed to state the rule, and none is claimed.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x538ca50`, no open pull request title mentions it or hash-bit-probe-loop, and its bytes overlap nothing in packets #1–#76.

## Scout note

The round-11 scout note listed this window (backup B5, the last round-11 item) with FDE `[0x538ca50, 0x538cad3)`, 131 bytes, 13 padding bytes, zero direct callers, and one R_X86_64_RELATIVE slot (0x5763838). Every element verified exactly. No numeric correction to the scout's numbers was needed. Two phrasing points are reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the zero direct sites are incoming calls — the two statements are about different directions and do not conflict; and the scout's "golden-ratio hash" shorthand is not adopted as a claim — the packet records only the constant `0x9e3779b9` as an observed immediate, and what that constant is "for" is not established from this window alone. The scout's "iterates r8d times" is confirmed with the signed-count qualification: a non-positive count returns 1 without probing.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_hash_bit_probe_loop.py --check research/work-items/foundation-hash-bit-probe-loop-94/evidence.json
python3 -m unittest tests.test_foundation_hash_bit_probe_loop -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x538ca50 --stop-address=0x538cae0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its thirteen padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b38d0` (this window) and `0x2b38e4` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

- Window: `[0x538ca50, 0x538cad3)`, 131 bytes, FDE at `.eh_frame` section offset `0x2b38d0`, CIE at offset 0, `zR` pcrel sdata4 (field VA `0xfb4df0` + sdata4 `0x43f7c60` = `0x538ca50`, range `0x83`), GNU `--dwarf=frames` confirmed. Thirteen `int3` padding bytes follow, to the 144-byte stride ending at `0x538cae0`; stride is not the FDE extent, and the checker locks body and padding separately. The next FDE starts exactly at `0x538cae0` (`[0x538cae0, 0x538caf1)`, 17 bytes). Body SHA-256 `a39e8a2e90c32f478d8f7cc3eb3e9aa9cbb5389a225463fa87a5131c3fc779ad`.
- Inputs, read directly from the bytes: `rdi` = struct pointer; `[rdi+0x8]` = table base pointer; `[rdi+0x10]` = round count, read as a signed 32-bit value (`r8d`); `[rdi+0x14]` = scale field, read as a zero-extended 32-bit value (`edx`); `rsi` = key, used whole in the block-offset product and by its high dword as the first probe value. The `mov %esi,%esi` at `0x538ca5a` zero-extends the low dword of the key, but `esi` is overwritten by `mov %r9d,%esi` before any use, so that zero-extension is dead and no claim rests on it.
- Block offset, verified from bytes: `edx = [rdi+0x14] >> 6` (logical shift); `rdx = edx * rsi` (wrapping 64-bit `imul`); `rdx >>= 32`; `rdx <<= 6`. The result is always a multiple of 64, so the probed block is the 64-byte block at `table base + offset`. The product uses the full 64-bit key, not just its high dword.
- Count gate, verified from bytes: `test %r8d,%r8d; jle 0x538cac4` — a non-positive signed count returns 1 immediately, without reading any table byte. A negative count is not a huge unsigned loop; the signed comparison is what the bytes do.
- First probe, verified from bytes: `rdi = table base + offset`; `r9 = key >> 32` (the high dword, via `shr $0x20,%r9`); `esi = r9d`; then `r9 >>= 0x1a` (byte index, bits 26..31, 0..63), `esi >>= 0x17` (bits 23..25), `and $0x7,%esi` (bit index 0..7), `movsbl (%rdi,%r9,1),%ecx`, `bt %esi,%ecx`, `jae 0x538cad0` (return 0 on a clear bit). The byte is read sign-extended, but only the tested bit matters, so the sign extension does not affect the result.
- Loop, verified from bytes: after a passing first probe, `esi` is zeroed and control jumps to the increment: `add $0x1,%esi`; `imul $0x9e3779b9,%eax,%eax` (32-bit wrap); `cmp %esi,%r8d`; `jne 0x538caa0` (probe the new value: `ecx = eax >> 0x1a` byte index, `edx = (eax >> 0x17) & 7` bit index, `movsbl (%rdi,%rcx,1),%ecx`, `bt %edx,%ecx`, `jae` to the zero return). A positive count `N` therefore probes exactly `N` times: probe 0 uses the key's high dword, probe `k` uses `high * 0x9e3779b9^k mod 2^32`. The loop has no other exit: every iteration either fails to the zero return or reaches the count comparison.
- Returns: `1` via `mov $0x1,%eax` (all probes set, or non-positive count) and `0` via `xor %eax,%eax` (first clear probed bit). No pointer, count, or table content is returned.
- Dead bytes, locked as bytes not behavior: the 2-byte `xchg %ax,%ax` at `0x538ca9e` sits between an unconditional `jmp` and the loop body and is targeted by no branch; the 6-byte `nopw` at `0x538caca` follows a `ret` and is targeted by no branch. Neither is claimed as executed code.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 target is `0x538ca50`. This is explicitly not a complete xref census: indirect calls and tail jumps are not covered by the scan.
- Data edge: exactly one relocation record in any `.rela.*` section names this window as addend — `R_X86_64_RELATIVE` at slot `0x5763838` in `.rela.dyn` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). It is reported as a slot list, not a single naming slot; nothing about the table holding the slot is claimed. No non-RELATIVE relocation type names this window.
- Nearest claimed window: two-hop field select `0x5361710` (packet #65), `0x2b340` away.
- Symbol hint, explicitly disclaimed: objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol far below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences

- The "hash bit-probe loop" label is an inference from the observed shape (a multiply recurrence feeding bit tests over a table block), kept separate from the observed rule above. Calling the constant `0x9e3779b9` a golden-ratio constant is the scout note's shorthand, not a fact established from this window; the packet claims only the immediate value.
- The 64-byte block, the bit-per-round structure, and the multiply recurrence resemble a membership filter, but the table's contents, the filter's parameters, and the caller's purpose are not established from this window alone, and no such claim is made.

## Unknowns

- What the struct fields at `+0x8`, `+0x10`, and `+0x14` mean in source terms, and what the probed table holds.
- Whether any caller reaches this window indirectly (the direct-call scan cannot see indirect calls or tail jumps).
- Whether the probed table is ever populated with the bits this loop tests, and what a "1" result causes the caller to do.

## Limits

- No stdlib type, source-level function, field meaning, table content, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming slot does not identify the window's provenance.
- The rule is stated for arbitrary 32-bit probe values and arbitrary table bytes; the actual table contents at runtime are not part of this evidence.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
