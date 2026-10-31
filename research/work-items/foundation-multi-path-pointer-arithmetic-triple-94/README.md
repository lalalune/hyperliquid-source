# foundation-multi-path-pointer-arithmetic-triple-94: what does the multi-path pointer-arithmetic triple window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 82-byte FDE window with fourteen padding bytes, the multi-path pointer-arithmetic rule with its exact field offsets, the exact incoming-call scan result (zero direct sites), and the one relocation slot.
- Excluded: what the node fields mean, what consumes the returned pair, any wider pointer-arithmetic family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a flag-selected pair — either a stored (base, limit) pair or a computed cursor (base + adjusted span) with the limit — with the two paths converging on the same (rax, rdx) return pair shape. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x50fa260`, no open pull request title mentions it or multi-path-pointer-arithmetic-triple, and its bytes overlap nothing in packets #1–#99.

## Scout note

The round-15 scout note listed this window (ranked #4, the last ranked item) with FDE `[0x50fa260, 0x50fa2b2)`, 82 bytes, 14 padding bytes, zero direct callers, one R_X86_64_RELATIVE slot `0x575ad00`, and nearest claimed window pointer-mark walk `0x50e69f0` (packet #88) `0x13870` away. Every element verified exactly except one branch-direction refinement: the scout described the window as having "forward branches only". The two `je` branches are forward, but the `jmp` at offset `0x3c` (bytes `eb e6`, disp −26) is a **backward join** to the shared tail at `0x50fa284`. It is not a loop: the join target falls through to `ret` with no cycle back, so the window still has no loop — but the branch inventory is two forward `je` branches plus one backward join, and that is what the checker locks.

## Pair-mate caveat

The adjacent window at `0x50fa860` (68 bytes) shares four field offsets with this one (`[rdi+0xa8]`, `[rdi+0xa0]`, `[rdi+0x300]`, `[rdi+0xd8]`) and is the pair mate. It is NOT claimed here. Its bytes show a different rule: it first gates on `cmpq $0x0,0x2f8(%rdi)` and returns early, it never takes the stored-pair path, and it never sets `rdx` to `[rdi+0x300]` — it returns the adjusted span pair instead. Shared offsets only; only `0x50fa260` is bound, so the pair is not double-claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_multi_path_pointer_arithmetic_triple.py --check research/work-items/foundation-multi-path-pointer-arithmetic-triple-94/evidence.json
python3 -m unittest tests.test_foundation_multi_path_pointer_arithmetic_triple -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x50fa260 --stop-address=0x50fa2c0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its fourteen padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x298028` (this window) and `0x29803c` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x298028` describes `[0x50fa260, 0x50fa2b2)`, 82 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fourteen `int3` bytes follow: the next FDE starts exactly at `0x50fa2c0` (record at `.eh_frame+0x29803c`, range to `0x50fa45d`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence (offsets relative to 0x50fa260)

```
 0: f3 0f 1e fa          endbr64
 4: 80 bf 40 02 00 00 01 cmpb   $0x1,0x240(%rdi)
11: 74 33                je     0x50fa2a0        ; stored-pair path
13: 80 bf d8 00 00 00 00 cmpb   $0x0,0xd8(%rdi)
20: 48 8b 97 a8 00 00 00 mov    0xa8(%rdi),%rdx   ; span
27: 48 8b 87 a0 00 00 00 mov    0xa0(%rdi),%rax   ; base
34: 74 14                je     0x50fa298        ; adjust path (byte == 0)
36: 48 8b 8f 00 03 00 00 mov    0x300(%rdi),%rcx  ; limit
43: 48 29 ca             sub    %rcx,%rdx
46: 48 01 d0             add    %rdx,%rax
49: 48 89 ca             mov    %rcx,%rdx
52: c3                   ret
53: 0f 1f 00             nopl   (%rax)           ; intra-body padding
56: 48 83 ea 08          sub    $0x8,%rdx
60: eb e6                jmp    0x50fa284        ; backward join to shared tail
62: 66 90                xchg   %ax,%ax          ; intra-body padding
64: 48 8b 8f 10 03 00 00 mov    0x310(%rdi),%rcx  ; stored limit
71: 48 8b 87 08 03 00 00 mov    0x308(%rdi),%rax  ; stored base
78: 48 89 ca             mov    %rcx,%rdx
81: c3                   ret
```

### Rule

- If byte `[rdi+0x240] == 1`: `(rax, rdx) = ([rdi+0x308], [rdi+0x310])`.
- Otherwise: `rax = [rdi+0xa0] + ([rdi+0xa8] − (8 if byte [rdi+0xd8] == 0 else 0) − [rdi+0x300])`, `rdx = [rdi+0x300]`. All arithmetic is 64-bit wrapping, matching the hardware.
- A flag value other than 1 takes the computed path: the test is `cmpb $0x1` followed by `je`, so only exactly 1 selects the stored pair.
- No field is written on any path: every `mov` is a load or register-to-register, and the checker pins all 82 body bytes.
- Branch targets exact: `je` at offset `0x0b` (2 bytes, disp `0x33`) lands on the stored-pair block at offset `0x40`; `je` at offset `0x22` (2 bytes, disp `0x14`) lands on the adjust block at offset `0x38`; `jmp` at offset `0x3c` (2 bytes, disp `0xe6` = −26) lands on the shared tail at offset `0x24`. The `nopl` (3 bytes) and `xchg` (2 bytes) between return blocks are intra-body alignment padding, not instructions with effects.

### Incoming calls and data edges

- Incoming: the `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.
- Data edge: exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x575ad00` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed.

## Inferences

- The label "multi-path pointer-arithmetic triple" is an inference from the observed rule: three pointer-ish quantities (base, span, limit) combined across two paths into one return pair. It is kept separate from the observed rule above.
- The convergence of both paths on the same `(rax, rdx)` shape suggests a single caller-side contract, but no caller is observed, so no caller purpose is claimed.

## Unknowns

- What the fields at `+0x240`, `+0xa0`, `+0xa8`, `+0xd8`, `+0x300`, `+0x308`, `+0x310` mean, and what structure `rdi` points at.
- Whether any indirect caller reaches this window; the scan cannot answer that.
- What the single relocation slot belongs to; it is a slot list, not a provenance claim.
- Which source-level function, if any, this window corresponds to.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
