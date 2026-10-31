# foundation-bounded-key-walk-94: what does the bounded key-walk window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 106-byte FDE window with six padding bytes, the bounded key-walk rule with its exact fields and per-path triple contents (including a scout correction below), the exact incoming-call scan result (one direct site), and the zero-slot relocation result.
- Excluded: what the nodes, words, or key mean, what the chain walks over, any wider walk-component claim, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a node-chain walk gated by two 16-bit words per node, counting steps, storing a three-qword triple whose exact contents differ per path. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1b26100`, no open pull request title mentions it or bounded-key-walk, and its bytes overlap nothing in packets #1–#120.

## Scout note

The round-23 scout note listed this window (ranked #1, the only ranked item this round) with FDE `[0x1b26100, 0x1b2616a)`, 106 bytes, 6 padding bytes, 8 preceding gap bytes, one direct caller (`0x2576999` in FDE `[0x25767b0, 0x2576b6d)`), zero naming relocation slots, and a twin guard of 12/106. Every element verified exactly — except the scout's summary of the stored triple, which the bytes correct (see below).

## Scout correction: the path-2 and path-3 triples do NOT store the input key

The scout note summarized all three paths as storing a "(node, steps, key) triple". The bytes support that summary only for path 1. The walk loop's `movzwl 0xe4(%rdx),%esi` at offset `0x3b` zero-extends the current node's +0xe4 word into `rsi`, clobbering the input key — so the path-2 store at offsets `0x4e`–`0x55` writes the previous node's +0xe4 gate word as its third field, not the key. Likewise the exhausted path writes `(0, last node, last index)`, with no key anywhere. The rule below and the checker's edge tests encode the bytes, not the note:

- Path 1 (key < word[first node + 0xe6]): store `(first node, index, key)`.
- Path 2 (walk stops at node N because word[N + 0xe6] > word[prev + 0xe4]): store `(N, steps, word[prev + 0xe4] zero-extended)`.
- Path 3 (chain exhausted, next node is 0): store `(0, last node, last index)`.

## Idiom disclosure, stated head-on

A whole-`.text` scan for the `movzx` word `[reg+0xe6]` idiom finds 27 FDEs of 400 bytes or fewer using it — all larger functions (197–377 bytes) that USE the field access, e.g. `0x1b26680` (350 bytes, `0x580` away) and the repeated 377-byte family at `0x286xxxx` / `0x494xxxx`. None is a pure small walk window, and byte-compares vs the nearest same-idiom windows are 3/106 (`0x1b26680`) and 5/106 (`0x13a9c60`) — not twins. The idiom's recurrence elsewhere does not make this window a population member. The twin guard below was re-run by this builder, not taken on scout trust.

## Peer distinction, stated head-on

This window sits in the #1039 (bridge VoteGlobal settings) region scan only by address — about `0x28D4` past the end of the peer function `voter_remove_kv` at `0x1b2382c` — but it appears in none of the peer's files (function-rows, twin-rows, call-sites, locations all grep 0 hits for `0x1b26100`), and its domain (node-chain walk with +0xe4/+0xe6 word gates) is distinct from the peer's bridge-settings writer claims. It is a neighbour by address only, not a sibling of the peer's claim. The peer lane is not claimed here. Provenance: #1039 REGION scan, distinct domain.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bounded_key_walk.py --check research/work-items/foundation-bounded-key-walk-94/evidence.json
python3 -m unittest tests.test_foundation_bounded_key_walk -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1b26100 --stop-address=0x1b26170 artifacts/node/94/hl-node
objdump -d --start-address=0x25767b0 --stop-address=0x2576b6d artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its six padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2e56c` (this window), `0x2e580` (the next FDE), and `0x3eb2cc` (the caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2e56c` describes `[0x1b26100, 0x1b2616a)`, 106 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Six `int3` bytes follow: the next FDE starts exactly at `0x1b26170` (record at `.eh_frame+0x2e580`, range to `0x1b2623a`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- Eight `int3` bytes precede the window (the previous FDE ends at `0x1b260f8`); that gap is padding, not code, and the checker locks it as a boundary.
- The window opens with `mov %rdi,%rax`, NOT `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x1b26100`.

- Offset `0x00`: `mov %rdi,%rax` — save the out pointer.
- Offset `0x03`: `mov (%rsi),%rdx` — first node load: rdx = [record].
- Offset `0x06`: `mov 0x8(%rsi),%rcx` — index load: rcx = [record+8].
- Offset `0x0a`: `mov 0x10(%rsi),%rsi` — key load: rsi = [record+0x10].
- Offset `0x0e`: `movzwl 0xe6(%rdx),%edi` — first gate word, zero-extended.
- Offset `0x15`: `cmp %rdi,%rsi` — compare key against the first gate word.
- Offset `0x18`: `jae 0x1b26130` — key >= first gate word: take the walk path.
- Offset `0x1a`: `mov %rdx,%rdi` — path 1: node into the store register.
- Offset `0x1d`: `mov %rdi,(%rax)` — store the node.
- Offset `0x20`: `mov %rcx,0x8(%rax)` — store the index.
- Offset `0x24`: `mov %rsi,0x10(%rax)` — store the key (still intact on this path).
- Offset `0x28`: `ret` — path-1 return.
- Offset `0x29`: `nopl 0x0(%rax)` — inter-path alignment padding.
- Offset `0x30`: `mov (%rdx),%rdi` — walk: next node load.
- Offset `0x33`: `test %rdi,%rdi` — exhaustion test.
- Offset `0x36`: `je 0x1b2615a` — next node is 0: take the exhausted path.
- Offset `0x38`: `inc %rcx` — step count increment.
- Offset `0x3b`: `movzwl 0xe4(%rdx),%esi` — current gate word, zero-extended into rsi (this clobbers the input key).
- Offset `0x42`: `mov %rdi,%rdx` — advance: current node becomes the next node.
- Offset `0x45`: `cmp 0xe6(%rdi),%si` — compare the new node's +0xe6 word against the gate word.
- Offset `0x4c`: `jae 0x1b26130` — new gate word <= gate word: loop.
- Offset `0x4e`: `mov %rdi,(%rax)` — path 2: store the stopping node.
- Offset `0x51`: `mov %rcx,0x8(%rax)` — store the step count.
- Offset `0x55`: `mov %rsi,0x10(%rax)` — store the gate word (not the key).
- Offset `0x59`: `ret` — path-2 return.
- Offset `0x5a`: `mov %rdx,0x8(%rax)` — exhausted: store the last node.
- Offset `0x5e`: `mov %rcx,0x10(%rax)` — exhausted: store the last index.
- Offset `0x62`: `movq $0x0,(%rax)` — exhausted: store 0.
- Offset `0x69`: `ret` — exhausted return.

### Data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site — `0x2576999`, inside caller FDE `[0x25767b0, 0x2576b6d)` — explicitly not a complete xref census. The caller FDE is retained in full in `caller.objdump.txt`.
- Relocations: zero `R_X86_64_RELATIVE` records in any `.rela.*` section name this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries) — no meaning claimed.
- Twin guard, re-run by this builder: full claimed-body byte-compare over 508 FDE bodies (packets #1–#120 claimed list plus known do-not-build windows; the unwindless packet #115 body compared separately) gives a top match of only 12/106 vs `0x51fccf0` / `0x51fcc60` / `0x51fcbd0` (129-byte bodies), and 8/98 vs the unwindless #115 body — not a twin. The nearest claimed window is `0x347350` away; the byte-compare is the operative guard, not distance.

## Inferences

- The "bounded key-walk" label is an inference from the observed rule: a chain walk gated by per-node words, with a step count and a triple store. The gate words' semantics, the nodes' type, and the key's meaning are not inferred.
- The three stored qwords share one out-pointer layout across paths, but their third field's meaning changes per path (key / gate word / last index). No single "triple" semantics is claimed.
- The window's lack of `endbr64` and its single caller are consistent with a private helper reached by one call site, but that is a consistency note, not a provenance claim.

## Unknowns

- What the nodes are, what the +0xe4/+0xe6 words represent, and what the key selects.
- Whether the caller at `0x2576999` is the only runtime caller (the scan covers direct `e8` sites only).
- Whether other chain-walk windows share this gate idiom beyond the 27 FDEs noted above; the idiom scan is a field-access census, not a component map.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the zero-slot result does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
