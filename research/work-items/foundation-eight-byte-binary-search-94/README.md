# foundation-eight-byte-binary-search-94: what does the 8-byte binary search window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 115-byte FDE window with 13 padding bytes, the 8-byte binary search rule with its exact branches, the exact incoming-call scan result (one direct site in one caller FDE), and the zero-naming-relocation scan result.
- Excluded: what the table entries mean, what the limit field represents, any wider binary-search family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a lower-bound binary search over 8-byte table entries with a limit shortcut and an empty-span path. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x52ca970`, no open pull request title mentions it or eight-byte-binary-search, and its bytes overlap nothing in packets #1–#108. It was also byte-compared against packet #76's window (see below) and is not a twin of it or of any other bound window.

## Scout note

The round-16 scout note listed this window (backup B4, the last real backup after ranked #1–#4 and backups B1–B2, with backup B3 rejected as a byte-identical twin of the div61 packet) with FDE `[0x52ca970, 0x52ca9e3)`, 115 bytes, 13 padding bytes, one direct caller (boundary-confirmed), no naming relocation, and nearest claimed window dual-zero test `0x5341920` (packet #36) `0x76fb0` away. Every scouted element verified exactly, with two refinements to the scout's rule summary, stated head-on below: (1) the count − 1 shortcut fires when key >= limit, not only when the key is above the limit; (2) the empty-span 0 applies only on the search path (key < limit) — an empty span with key >= limit returns count − 1 wrapped to all-ones.

## Caller caveat

One direct `e8` call site reaches this window, confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x52cab17` (FDE `0x52cab00..0x52cab83`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

## Packet #76 distinction and twin check, stated head-on

This window sits next to packet #76 (16-byte binary search) and the two rules are distinct in element size, dereference depth, and return convention — no shared primitive is claimed:

- Packet #76 walks 16-byte entries, reads only the first qword of each entry as a pointer to a cell whose first qword is the key (a double dereference `[[entry]]`), and returns a pointer to the first entry whose key is >= the search key (unsigned), or the table end. It has 14 direct callers in 10 caller FDEs.
- This window walks 8-byte entries, reads each entry's qword directly as the key (a single dereference `[entry]`), and returns an index: the first entry whose key is >= the search key (unsigned), the insertion point when every probed key is smaller, count − 1 on the limit shortcut, or 0 for an empty span on the search path. It has 1 direct caller in 1 caller FDE.
- Twin check: the two bodies differ in size (115 vs 106 bytes) and in SHA-256 (`9565325f…` vs `6c475fe9…`), and the instruction sequences differ throughout (different entry stride, different midpoint scaling, different return computation). This window is not a re-instantiation of packet #76, and it was not found identical to any other bound window either — unlike round-16 backup B3, which was rejected for exactly that reason.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_eight_byte_binary_search.py --check research/work-items/foundation-eight-byte-binary-search-94/evidence.json
python3 -m unittest tests.test_foundation_eight_byte_binary_search -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x52ca970 --stop-address=0x52ca9f0 artifacts/node/94/hl-node
objdump -d --start-address=0x52cab00 --stop-address=0x52cab83 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 13 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the one caller FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2ac1ec` (this window), `0x2ac200` (the next FDE), and `0x2ac250` (the caller FDE), plus the CIE at offset `0` (all three FDEs). The checker locks these raw FDE records and the CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

- FDE record at `.eh_frame` section offset `0x2ac1ec`, CIE at offset `0`
  (`zR`, pcrel sdata4), range 115 bytes. The 115-byte body ends at `0x52ca9e3`;
  13 `int3` padding bytes run to the 128-byte stride ending at `0x52ca9f0`,
  where the next FDE starts (`[0x52ca9f0, 0x52caa4c)`, section offset
  `0x2ac200`, same CIE). Stride is not the FDE extent; the checker locks
  body and padding separately.
- Decoded instructions, in order, all verified from bytes (all arithmetic
  64-bit; the final results are 64-bit rax values):
  - `endbr64`; `mov (%rdi),%r8` (lo = table lo); `mov 0x8(%rdi),%rcx`
    (hi = table hi); `sub %r8,%rcx` (span_bytes = hi − lo);
    `mov %rcx,%rax`; `sar $0x3,%rax` (count = span_bytes >> 3, arithmetic);
    `mov %rax,%rdx` (count saved); `cmp 0x18(%rdi),%rsi`
    (limit vs key, AT&T order: computes key − limit);
    `jb 0x52ca998` (taken when key < limit unsigned) into the search path.
  - Shortcut path (key >= limit): `sub $0x1,%rax` (count − 1); `ret`.
    The 5-byte `nopl` at `0x52ca993` is intra-body alignment padding.
  - Search path: `test %rcx,%rcx`; `jle 0x52ca9e0` (span_bytes <= 0
    signed → empty path: `xor %eax,%eax`; `ret`, returning 0).
  - Loop: `mov %r8,%rax` (lo); `mov %rdx,%rcx` (count);
    `sar $1,%rcx` (mid = count >> 1, arithmetic);
    `lea (%rax,%rcx,8),%rdi` (probe = lo + mid*8);
    `cmp %rsi,(%rdi)` (computes entry − key);
    `jae 0x52ca9d0` (taken when entry >= key unsigned) into the found-ge path.
  - Less-than path: `sub %rcx,%rdx` (count −= mid);
    `lea 0x8(%rdi),%rax` (lo = probe + 8); `sub $0x1,%rdx` (count −= 1);
    `test %rdx,%rdx`; `jg 0x52ca9a0` (count > 0 → loop again);
    else fall through to `sub %r8,%rax`; `sar $0x3,%rax`
    ((lo − lo0) / 8 = index); `ret`.
    The 10-byte `nopw` at `0x52ca9c7` is intra-body alignment padding.
  - Found-ge path: `test %rcx,%rcx`; `je 0x52ca9bf` (mid == 0 → the
    index computation above, where lo is the probe address itself, so the
    result is the probe's index); else `mov %rcx,%rdx` (count = mid);
    `jmp 0x52ca9a0` (loop again with the same lo).
    The 6-byte `nopw` at `0x52ca9da` is intra-body alignment padding.
- Rule, stated literally: let `count = (hi − lo) >> 3` (arithmetic shift,
  truncating a non-multiple-of-8 span) and let `limit = [rdi+0x18]`.
  If `key >= limit` (unsigned), return `count − 1` without searching.
  Else if `span_bytes <= 0` (signed), return 0 without reading any entry.
  Else run the sar-midpoint loop above and return the lower-bound index:
  the first entry whose key is >= `key` (unsigned), or the insertion point
  (one past the last probed entry) when every probed key is < `key`.
  All arithmetic wraps at 64 bits. No field is written.
- Limit-shortcut refinement, stated exactly: the `jb` at `0x52ca98c` is
  taken when `key < limit` (unsigned), so the shortcut fires on
  `key >= limit` — including `key == limit`, where it returns `count − 1`
  even though the search would have found the matching index. The scout's
  "count − 1 when the key is above the limit" is therefore narrowed to
  "count − 1 when the key is >= the limit".
- Empty-span refinement, stated exactly: the `jle` empty path is reachable
  only from the search path, so an empty span returns 0 only when
  `key < limit`. An empty span with `key >= limit` takes the shortcut and
  returns `count − 1 = −1` wrapped to all-ones. Both edges are pinned in
  the checker.
- Negative-span branch, stated without smoothing: on the search path a
  negative span also takes the `jle` path and returns 0 without reading any
  entry; on the shortcut path it returns the (negative) `count − 1`. The
  table itself is not interpreted for a negative span.
- Unsigned-compare caveat, stated exactly: both the limit check (`jb`) and
  the entry check (`jae`) are unsigned. A signed reading would differ on
  keys or entries with the high bit set; the pinned edge
  (entries `[2^63]`, limit `2^64 − 1`, key 1 → 0) distinguishes them.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly one direct `e8` site, boundary-confirmed above. This is
  explicitly not a complete xref census.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan: 80,022 `.rela.dyn` +
  278 `.rela.plt` entries).
- Entry shape: the window opens with endbr64; it has six conditional
  branches plus one unconditional jmp join, three rets, and no calls inside.

## Inferences

- The label "eight-byte binary search" is an inference from the instruction
  sequence (sar midpoint loop over 8-byte entries, index return). It is
  kept separate from the observed rule above.
- Nothing is inferred about what the table entries represent, what the
  limit field bounds, or which source-level function this window belongs to.

## Unknowns

- Whether the single caller passes a sorted table, and what consumes the
  returned index, is unknown; the caller FDE is retained but its purpose is
  not claimed.
- Whether this window shares a source-level helper with packet #76 is
  unknown and not claimed; only the byte-level rule differences above
  are established.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is
  claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a
  naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated
  progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was
  copied, and every claim is grounded in target bytes for node #94.
