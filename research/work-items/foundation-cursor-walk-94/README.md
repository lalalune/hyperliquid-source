# foundation-cursor-walk-94: what does the cursor walk loop compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 81-byte FDE window, its 15 int3 padding bytes, the single direct call site, the absence of a naming relocation, and the exact loop rule.
- Excluded: the nodes' meaning, the cursor/limit pair's provenance, any caller behavior beyond call-site scanning, the next FDE, other walk helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a loop that advances a cursor in 0x38 steps, checks two bytes per visited node, and returns 1 exactly when an advance lands on the limit. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x3c1d690`, no open pull request title mentions it or cursor-walk, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, field-inequality, bsr-lookup, multiply-mix-div61, global-clamp, or two-field-byte-gate packets.

This window is bound **alone**. No census of similar windows is claimed.

## Scout correction (read this first)

The round-8 scout shorthand said: "else cursor = next+0x38 and repeat". Taken literally, that skips a node: after the first iteration, the cursor would become `next+0x38` and the next iteration would check that node, never checking `next` itself. The retained bytes show the opposite — **every 0x38-step node is checked, none skipped**. The second iteration checks the node held in `rdx` (the previous advance) at `0x3c1d6cf`/`0x3c1d6d5` before advancing again, and the loop-back at `0x3c1d6db` returns to the limit compare at `0x3c1d6c0` with the new advance in `rdx`. The checker locks the verified bytes, not the scout summary.

Two smaller scout gaps, stated for completeness rather than as corrections: the scout did not mention that the first iteration's tag-3 check is redundant (both the tag-3 branch and the tag-2 branch return 0 with eax already zeroed, so the net rule is simply "tag must be exactly 2" in every iteration), nor that the cursor slot is mutated before the node checks, so a failing return leaves `*(rdi)` advanced past the failed node. Both are locked by the checker and the edge tests.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_cursor_walk.py --check research/work-items/foundation-cursor-walk-94/evidence.json
python3 -m unittest tests.test_foundation_cursor_walk -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3c1d690 --stop-address=0x3c1d6f0 artifacts/node/94/hl-node
objdump -d --start-address=0x3362f30 --stop-address=0x3362fc2 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains the caller FDE's disassembly, including the call site. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x1beec4`, the next FDE at `0x1beed8`, and the caller FDE at `0x11818c`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the next and caller FDE records' raw bytes with their GNU-decoded ranges.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x1beec4` describes `[0x3c1d690, 0x3c1d6e1)`, 81 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the entry-equal `ret` at `0x3c1d6e0` is inside the FDE; the fail-path `ret` at `0x3c1d6dd` is also inside it).
- The stride to the next FDE at `0x3c1d6f0` is 15 int3 bytes (`cc` × 15) from `0x3c1d6e1` to `0x3c1d6f0`, where the next FDE starts (range 0x10e bytes to `0x3c1d7fe`). The checker locks body and padding separately; stride is not the FDE extent.

### Instruction walk

All offsets are relative to the FDE start `0x3c1d690`. Registers: `rsi` holds the node being checked in the first iteration, `rdx` the advance; later iterations swap roles (`rdx` is the node, `rsi` the advance). `rcx` holds the limit throughout.

1. `mov (%rdi),%rsi` (bytes 0–2): `cursor = *(rdi)`.
2. `mov 0x8(%rdi),%rcx` (bytes 3–6): `limit = *(rdi + 8)`.
3. `cmp %rcx,%rsi` (bytes 7–9).
4. `je 0x3c1d6de` (bytes 10–11): if `cursor == limit`, go to step 21 (zero, return 0) with `*(rdi)` unchanged.
5. `lea 0x38(%rsi),%rdx` (bytes 12–15): `next = node + 0x38`.
6. `mov %rdx,(%rdi)` (bytes 16–18): `*(rdi) = next` — the cursor slot is mutated **before** the node checks below, so a failing return leaves it advanced.
7. `movzbl 0x9(%rsi),%r8d` (bytes 19–23): `tag = *(node + 9)`.
8. `xor %eax,%eax` (bytes 24–25): return value preset to 0.
9. `cmp $0x3,%r8b` (bytes 26–29) + `je 0x3c1d6dd` (bytes 30–31): tag 3 → return 0.
10. `cmp $0x2,%r8b` (bytes 32–35) + `jne 0x3c1d6dd` (bytes 36–37): tag != 2 → return 0. Net effect of steps 9–10: tag must be exactly 2.
11. `cmpb $0x0,(%rsi)` (bytes 38–40) + `jne 0x3c1d6dd` (bytes 41–42): first byte of the node != 0 → return 0.
12. `nopl 0x0(%rax,%rax,1)` (bytes 43–47): alignment inside the loop body, locked as body bytes.
13. `cmp %rcx,%rdx` (bytes 48–50) + `sete %al` (bytes 51–53) + `je 0x3c1d6dd` (bytes 54–55): if `next == limit`, return 1 (sete set al = 1 and the upper bits of eax are still zero from step 8); otherwise al = 0 and execution falls through.
14. `lea 0x38(%rdx),%rsi` (bytes 56–59): `next2 = next + 0x38`.
15. `mov %rsi,(%rdi)` (bytes 60–62): `*(rdi) = next2`.
16. `cmpb $0x2,0x9(%rdx)` (bytes 63–66) + `jne 0x3c1d6dd` (bytes 67–68): tag of the previous advance != 2 → return 0. This is the step the scout shorthand skipped: the node checked here is `rdx`, the previous advance, not `rsi`.
17. `cmpb $0x0,(%rdx)` (bytes 69–71): first byte of that node.
18. `mov %rsi,%rdx` (bytes 72–74): `rdx = next2`.
19. `je 0x3c1d6c0` (bytes 75–76): if that first byte == 0, loop back to step 13 with the new advance in `rdx`; otherwise fall through to step 21 (return 0).
20. `ret` at `0x3c1d6dd` (byte 77): the shared fail/success return.
21. `xor %eax,%eax` (bytes 78–79) + `ret` at `0x3c1d6e0` (byte 80): the entry-equal path, return 0.

### Rule

```
if *(rdi) == *(rdi+8): return 0                    # no mutation
node = *(rdi)
loop:
    next = node + 0x38
    *(rdi) = next                                  # mutation before checks
    if *(node+9) != 2: return 0
    if *(node+0) != 0: return 0
    if next == *(rdi+8): return 1
    node = next
```

Equivalently: return 1 iff walking in 0x38 steps from the entry cursor through nodes with (tag byte at +9 == 2, first byte == 0) lands exactly on the limit; the limit itself is never dereferenced. The return value is fully determined (eax is zeroed on the entry-equal path and at the first iteration before any return, and `sete` only sets the low byte), so no low-byte-only caveat applies here, unlike packets #27/#32.

### Termination note

The window has no bound check beyond equality with the limit. A limit that is not reachable in 0x38 steps from the entry cursor, with all visited nodes passing, does not terminate by itself; termination then depends on a node failing the checks (or on an access outside mapped memory, which the window does not guard against). This is a property of the retained bytes, not a claim about any caller's invariants.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` call site — `0x3362fb8` (bytes `e8 d3 a6 8b 00`, target `0x3c1d690`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x3362f30..0x3362fc2`) — explicitly not a complete xref census. The caller sets `rdi` to a stack address (`lea 0x8(%rsp),%rdi`) immediately before the call, after storing two words at `rsp+8` and `rsp+0x10`; caller purpose beyond that call-site setup is not claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The "cursor walk" label is an inference from the instruction shape: a cursor slot advanced in fixed steps, two per-node byte checks, and a limit-equality return. It is kept separate from the observed rule above.
- The cursor/limit pair may be fields of one structure addressed from rdi, but no field meaning or structure layout is claimed.
- The 0x38 step and the (tag 2, first byte 0) node shape may describe a list or table entry, but no container type is claimed.

## Unknowns

- What the nodes mean, and what source-level function or type this window belongs to.
- Whether any indirect or PLT-mediated caller exists; the byte-pattern scan covers direct `e8` sites only.
- The provenance of the window (stdlib, crate, or private helper); the absence of a naming relocation does not identify it.
- What invariants callers rely on for termination when the limit is off-lattice.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
