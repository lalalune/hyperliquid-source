# RE-002: ZSTD_count 0x6241700 (node #115)

Task: RE-002 (build provenance / dependency window). Bounded question:
what does the 211-byte leaf routine at 0x6241700 return for two byte
ranges and a limit, and where is it used?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). Vendor census member
`7c9960efb53c0b35-zstd_lazy.o`, rlib `libzstd_sys-c8c5b6f4c7c3aee0.rlib`,
crate `zstd-sys`, candidate versions `2.0.15+zstd.1.5.7` /
`2.1.2+zstd.1.5.7`, symbol `ZSTD_count`.

## Answer

The routine is zstd's match-length counter. It is a leaf: it calls
nothing, allocates nothing, and reads only the two byte ranges it is
given. From the disassembly in main.txt:

  size_t ZSTD_count(const BYTE* pIn, const BYTE* pMatch, const BYTE* pInLimit)

`rdi` = pIn, `rsi` = pMatch, `rdx` = pInLimit. It returns the number of
leading bytes pIn and pMatch share, never exceeding the bytes available
before pInLimit:

  **result = min(lcp(pIn, pMatch), pInLimit - pIn)**

Behaviour, pinned from the disassembly:

1. **8-byte tier.** While `pIn <= pInLimit - 8`, load one qword from
   each range (`mov (%rsi),%rax` / `mov (%rdi),%rdi`) and compare them.
   Equal qwords advance both pointers by 8 (`0x6241717`, `0x62417c0`).
   The first unequal qword (`0x6241790`) returns
   `tzcnt(pIn_qword ^ pMatch_qword) >> 3` added to the bytes already
   matched: the count of equal low-order bytes in that qword. x86 is
   little-endian, so this is exactly the leading equal-byte count at
   that offset.
2. **4-, 2-, 1-byte tiers.** After the qword loop, a dword tier
   (`pIn <= pInLimit - 4`, `0x624175c`), then a word tier
   (`pIn <= pInLimit - 2`, `0x624176b`), then a byte tier
   (`pIn < pInLimit`, `0x6241778`); each advances the pointer on a
   match and falls through on a mismatch.
3. **The cap.** The return is always `current pIn - pIn_start`
   (`sub %rcx,%rax`, `0x6241743`/`0x6241786`). Every load is guarded by
   the tier bounds, so the routine never reads at or beyond pInLimit
   and the result never exceeds `pInLimit - pIn`. It never reads before
   pIn.
4. The routine is not entered through an `endbr64` (its first bytes are
   `4c 8d 42 f9`, `lea -0x7(%rdx),%r8`), it is a leaf with no calls,
   and it stores nothing.

The closed form `min(lcp, limit)` and the four-tier walk were
cross-checked on 200,000 random inputs and over the full 2,400-case
generated sweep, both re-derived in memory by the test suite
(`tools/zstd_count_6241700_115.py`, `tests/test_zstd_count_6241700_115.py`).
`cases.tsv` is the **reviewable** 300-case ledger (every hand-written
structural cell that fits in a readable line, plus a deterministic
stride sample of the sweep). The exhaustive sweep is not committed as
a 1.6 MB blob because a blob is not reviewable evidence.
`target_body_sha256 == source_body_sha256`: the census records the body
as raw-equal to its public source bytes, with **no relocations**, so no
relocation field is zeroed.

## Consumers: what the callers depend on

Census (executable-LOAD-segment E8/E9 scan, rel32 resolved, each
candidate Capstone-validated at the instruction boundary by linear
disassembly from its enclosing FDE start, callers grouped by that
FDE; reproduced by census.py and re-run inside verify.py): **25 direct
calls, 0 tail jumps, 11 distinct caller FDEs**, no stored qwords and no
RELATIVE relocations. The call sites are listed in callers.tsv.

**The byte match above is already in the vendor comparison registry;
what this packet adds is the contract the callers place on the
routine.** For every call site `caller_use.tsv` records the first
instruction that reads the returned count (Capstone operand access
flags, scanning forward inside the enclosing FDE) and classifies it:

| consumer | sites | first read |
|---|---|---|
| length-arithmetic (folded into a running length) | 19 | `add rcx, rax`, `add r10, rax`, `add rbp, rax`, `add rax, 4` |
| store-pass (stored or passed on) | 5 | `mov r11/rbx/r13/rbp, rax` |
| overwritten before being read | 1 | `mov eax, 1` |

The callers therefore depend on the count being an **exact,
bounded, forward** common-prefix length: a wrong byte would corrupt a
running match length, and a value past `pInLimit - pIn` would overrun
the accumulator. Nine of the 25 sites add a constant `4` to it
(`add rax, 4`), i.e. they consume `count + 4` — zstd's `MINMATCH + 1`
match-length offset. That is a semantic fact the raw byte match does
*not* state, and it is what makes this reconstruction usable by a
caller-side check: a reimplementation of the callers must produce
`count + 4` as the encoded match length.

The call sites sit in the zstd match finders (the `zstd_lazy` object's
own neighbours 0x6250f80..0x6274xxx), which use this routine to
measure how far a candidate match extends before the block limit. The
identification of each caller FDE as a specific named zstd function is
inference from the region and the call shape; the pinned facts are this
routine's own algorithm, the 25 call sites with their enclosing FDE
bounds, and each site's consumer class.

## Evidence notes

- main.txt is the raw `objdump -d` listing of the whole routine,
  verbatim (encoded bytes and instruction text). The objdump symbol
  header is normalized to the bare binary name and the nearest-symbol
  annotations objdump adds to branch targets are dropped, so the file
  carries no machine-specific path and no misattributed symbol. The
  mnemonics in it (e.g. `tzcnt`) are genuine instructions present in
  the target binary.
- frames.txt is the .eh_frame entry covering the routine
  (`pc=0000000006241700..00000000062417d3`), read with `readelf -wf`.
- relocations.txt records the empty relocation set and both body
  hashes from the vendor census.
- records.json holds semantic records (context, caller census,
  observations, unknowns, environment limits), not a per-instruction
  list; instruction detail lives only in main.txt.
- verify.py re-checks the manifest, regenerates main.txt byte-for-byte
  and every instruction's bytes against the raw binary, regenerates the
  caller census and the caller-consumer census, checks the FDE bounds
  and the census body hash, replays the committed ledger, and asserts
  the ledger is the generated subset (with the 2,400-case sweep still
  present in the generator).

Reproduce the excerpt:

    objdump -d --start-address=0x6241700 --stop-address=0x62417d3 \
        artifacts/node/115/hl-node

## Unknowns

- Behaviour when pMatch supplies fewer readable bytes than the qword
  tier reads (the binary reads qwords from both ranges). Every caller
  passes pMatch pointing into the same block, so this is not
  characterized; the model requires both ranges to supply `limit`
  bytes.
- How each of the 25 callers uses the count *beyond* its first read
  (the consumer class and the `+4` offset are pinned; the full
  dataflow of a match length through the sequence encoder is not).
- The body is byte-identical in three identical source objects
  (`identical_source_count` = 3); only address 0x6241700 is bound.

## Environment limits

This work used static disassembly only (`objdump`/`readelf` on the
digest-verified local binary). No cargo/rustc, Ghidra or git-lfs was
needed, and the captured node was never executed. The model in
tools/zstd_count_6241700_115.py is a Python transcription of the
pinned algorithm with an independently written tier walk, not a build
of node or zstd code.
