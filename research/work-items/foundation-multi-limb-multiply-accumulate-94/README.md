# foundation-multi-limb-multiply-accumulate-94: what does the multi-limb multiply-accumulate window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 123-byte FDE window with five padding bytes, the 52-bit-limb multiply-accumulate rule with its exact constant and masks, the exact incoming-call scan result (three direct sites, each boundary-confirmed in its own caller FDE), and the zero naming-relocation-slot result.
- Excluded: what the five-limb integer represents, what the constant 0x1000003d1 is for, what the callers do with the updated integer, any wider multiply-accumulate family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a five-limb multiply-accumulate with a fixed constant, fixed 52-bit masks, and a fixed carry chain, with no call inside and a single return. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x56327f0`, no open pull request title mentions it or multi-limb-multiply-accumulate, and its bytes overlap nothing in packets #1–#113.

## Scout note

The round-19 scout note listed this window (ranked #2) with FDE `[0x56327f0, 0x563286b)`, 123 bytes, 5 padding bytes, zero branches, zero calls inside, 3 direct callers (call sites boundary-confirmed in FDEs `0x563b330`, `0x563b840`, `0x563ff20`), 0 naming slots, and nearest claimed window `0x56544a0` `0x21cb0` away. Every element verified exactly; no correction was needed.

## Caveats, stated head-on

- **NOT a twin of rejected round-16 backup B3.** Round-16 backup B3 `0x54ca1c0` (stateful multiply-mix with table-byte lookup, 87 bytes) was rejected as a byte-identical twin of the div61 packet and is excluded from building. This window was byte-compared against it directly: only **3/87** bytes identical over the overlap, with a different size (123 vs 87) and a different rule (52-bit-limb multiply-accumulate with carry chain, no table-byte lookup). It is not that window, not a variant of it, and nothing here re-claims B3.
- **Peer-gap distinction.** The nearest peer PR in this neighbourhood (live #981, the unwindless-boundary PR) covers a code-filled gap ending at `0x5631f00`. This window starts at `0x56327f0`, past that gap end, under its own FDE with its own rule. It is NOT one of the peer's two gap candidates: different location, different FDE, different rule. Nothing here re-claims, re-states, or grades the peer's gap work.
- **Nearest-claimed distinction.** The nearest claimed packet window `0x56544a0` is `0x21cb0` away, and byte-compare over this window's 123 bytes gives only 3/123 identical — different rule, not a twin.
- **Symbol-label disclaimer.** GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it. In particular, no stdlib or private provenance is claimed either way.
- **Constant-purpose disclaimer.** The constant `0x1000003d1` and the 52-bit limb shape are locked as literal arithmetic only. No claim is made about what number system, field, or conversion the constant belongs to.
- **Caller scale, stated plainly.** Three direct callers is a small, retained fact (all three caller FDEs are kept in `caller.objdump.txt`), not a population claim. The byte-pattern scan is not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.
- **Thinness, stated plainly.** This is a single-purpose window: one multiply, one fold, one carry chain, one return. What it is not is ambiguous — the constant, the masks, the shift amounts, and the carry order are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_multi_limb_multiply_accumulate.py --check research/work-items/foundation-multi-limb-multiply-accumulate-94/evidence.json
python3 -m unittest tests.test_foundation_multi_limb_multiply_accumulate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x56327f0 --stop-address=0x5632870 artifacts/node/94/hl-node
objdump -d --start-address=0x563b330 --stop-address=0x563b83c artifacts/node/94/hl-node
objdump -d --start-address=0x563b840 --stop-address=0x563ecb5 artifacts/node/94/hl-node
objdump -d --start-address=0x563ff20 --stop-address=0x5640295 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its five padding bytes. The `caller.objdump.txt` file retains complete disassembly of all three caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2d8140` (this window), `0x2d8154` (the next FDE), `0x2d87fc`, `0x2d8864` and `0x2d89e8` (the caller FDEs), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2d8140` describes `[0x56327f0, 0x563286b)`, 123 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Five `int3` bytes follow: the next FDE starts exactly at `0x5632870` (record at `.eh_frame+0x2d8154`, range to `0x5632975`). The unwind-index stride is therefore 128 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `mov 0x20(%rdi),%rdx`, not `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x56327f0`. `rax` is set to `rdi` at the start, so all stores land on the same five-qword integer the loads read: the update is in place.

- Offset `0x00`: `mov 0x20(%rdi),%rdx` — high limb load.
- Offset `0x04`: `mov %rdi,%rax` — base copy for the stores.
- Offset `0x07`: `movabs $0xffffffffffff,%r8` — 48-bit mask.
- Offset `0x11`: `movabs $0x1000003d1,%rcx` — fold constant.
- Offset `0x1b`: `movabs $0xfffffffffffff,%rsi` — 52-bit mask.
- Offset `0x25`: `and %rdx,%r8` — low 48 bits of the high limb.
- Offset `0x28`: `shr $0x30,%rdx` — high limb's top bits.
- Offset `0x2c`: `imul %rcx,%rdx` — top bits times the constant.
- Offset `0x30`: `add (%rdi),%rdx` — fold into limb 0.
- Offset `0x33`: `mov %rdx,%r9` — product copy.
- Offset `0x36`: `and %rsi,%rdx` — new limb 0 (52-bit mask).
- Offset `0x39`: `shr $0x34,%r9` — first carry.
- Offset `0x3d`: `add 0x8(%rdi),%r9` — carry into limb 1.
- Offset `0x41`: `mov %rdx,(%rax)` — store limb 0.
- Offset `0x44`: `mov %r9,%rdi` — carry copy.
- Offset `0x47`: `and %rsi,%r9` — new limb 1.
- Offset `0x4a`: `shr $0x34,%rdi` — second carry.
- Offset `0x4e`: `add 0x10(%rax),%rdi` — carry into limb 2.
- Offset `0x52`: `mov %r9,0x8(%rax)` — store limb 1.
- Offset `0x56`: `mov %rdi,%rcx` — carry copy.
- Offset `0x59`: `and %rsi,%rdi` — new limb 2.
- Offset `0x5c`: `shr $0x34,%rcx` — third carry.
- Offset `0x60`: `add 0x18(%rax),%rcx` — carry into limb 3.
- Offset `0x64`: `mov %rdi,0x10(%rax)` — store limb 2.
- Offset `0x68`: `and %rcx,%rsi` — new limb 3.
- Offset `0x6b`: `shr $0x34,%rcx` — final carry.
- Offset `0x6f`: `add %r8,%rcx` — final carry plus the high limb's low 48 bits.
- Offset `0x72`: `mov %rsi,0x18(%rax)` — store limb 3.
- Offset `0x76`: `mov %rcx,0x20(%rax)` — store the new high limb.
- Offset `0x7a`: `ret` — single return on every path.

The 52-bit limb shape is fixed by the bytes, not assumed: each new limb is masked with `0xfffffffffffff` and each carry is the value shifted right by `0x34` (52), so every carry into the next limb is exactly the overflow above 52 bits. The final high limb is NOT masked to 52 bits — it is the final carry plus the low 48 bits of the old high limb, stored whole.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` sites whose rel32 lands on the window start, each boundary-confirmed inside its own caller FDE:

- `0x563b803`, inside FDE `0x563b330..0x563b83c`.
- `0x563bc5f`, inside FDE `0x563b840..0x563ecb5`.
- `0x5640242`, inside FDE `0x563ff20..0x5640295`.

GNU objdump's own disassembly of each caller FDE resolves each site to this window start, independently confirming the scan. This is explicitly not a complete xref census.

### Relocations

No `R_X86_64_RELATIVE` record in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The window carries zero naming slots.

## Inferences

- The "five-limb, 52-bit" label is an inference from the mask/shift pattern, kept separate from the observed rule: the bytes fix the arithmetic, not the name.
- The "multiply-accumulate" label is an inference from the multiply-then-add-then-carry shape, kept separate from the observed rule.

## Unknowns

- What the five-limb integer represents, and what the constant `0x1000003d1` is for.
- What the three callers do with the updated integer, and whether they share a purpose.
- Whether other multiply-accumulate windows exist in the binary, and whether this one belongs to a family.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of relocation slots does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
