# RE-002: blst get_wval_limb 0x5d0ed60 (node #115)

Task: RE-002 (build provenance / dependency window). Bounded question:
what does the 84-byte leaf routine at 0x5d0ed60 return for a byte
string, a bit offset and a bit width, and what do its callers depend on?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json). Vendor census member
`4858b6d10aa81d56-server.o` (blst's `src/server.c`), rlib
`libblst-51b314b09d0de342.rlib`, crate `blst`, candidate versions
`0.3.15` / `0.3.16` / `0.3.17`, symbol `get_wval_limb`, `native` true.

## Answer

The routine reads a small bit-field window out of a little-endian
bit-packed byte string. It is a leaf: it calls nothing, allocates
nothing, stores nothing, and reads only the bytes the field spans. From
the disassembly in main.txt:

  limb_t get_wval_limb(const byte *w, size_t bitpos, size_t nbits)

`rdi` = w, `rsi` = bitpos, `rdx` = nbits. With

    first = bitpos >> 3
    span  = ((bitpos + nbits - 1) >> 3) - first

the result is the little-endian window of the `span + 1` spanned bytes,
shifted down by the bit offset:

  **result = (Σ over j in [0, span] of w[first + j] << (8·j)) >> (bitpos & 7)**

Behaviour, pinned from the disassembly:

1. **Bit offset to byte index.** `shr $0x3,%rsi` / `add %rsi,%rdi`
   (0x5d0ed63, 0x5d0ed75): the pointer moves to the first spanned byte.
2. **The byte span.** `lea -0x1(%r9,%rdx,1),%rax` / `shr $0x3,%rax` /
   `sub %rax,%rsi` (0x5d0ed70..0x5d0ed7c) leave `rsi` holding
   `first − last`, the negated span, which is then counted up to zero.
3. **At most four bytes.** The loop body (0x5d0ed81..0x5d0eda8) runs
   exactly four times: `add $0x8,%ecx` against `cmp $0x20,%ecx`. Each
   iteration reads one byte, shifts it left by the running bit counter
   and ORs it into an accumulator.
4. **Only the spanned bytes contribute.** `mov %rsi,%r8` /
   `sar $0x3f,%r8` (0x5d0ed87, 0x5d0ed90) turn the *previous* `rsi`
   into an all-ones mask while it is still negative, and into zero once
   it reaches zero. Exactly `span + 1` iterations OR in a byte; the
   rest OR in zero, so a byte past the field can never leak in. This is
   the mechanism the `mask` case group exercises directly (bytes past
   the field set to `0xFF`).
5. **The pointer steps with the span.** `shr $0x3f,%rdx` /
   `add %rdx,%rdi` (0x5d0ed9e, 0x5d0eda2) advance the pointer by one
   only while `rsi` is still negative, so the `j`-th contributing byte
   is `w[first + j]` shifted by `8·j`.
6. **The bit offset is dropped last.** `mov %r9d,%ecx` /
   `and $0x7,%ecx` / `shr %cl,%rax` (0x5d0edaa..0x5d0edb3).

### The window is not masked to `nbits`

There is no mask-to-`nbits` step anywhere in the routine. The result is
the whole spanned window, which contains the requested field in its low
bits and can carry **up to seven extra high bits** from the last
spanned byte whenever the field does not end on a byte boundary:

    get_wval_limb(b"\xa5", 0, 4) -> 0xA5   (the 4-bit field is 0x05)
    get_wval_limb(b"\xff\xff", 4, 8) -> 0xFFF   (the 8-bit field is 0xFF)

That is an observation of these bytes, not an inference from the crate:
the routine has no such instruction, and the callers supply the mask
themselves (next section). Result therefore depends only on
`(w[first..first+span], bitpos)`; `nbits` enters only through the span.

Because the loop shifts at most 32 bits, a field spanning more than
four bytes would be truncated. The model rejects that case rather than
guess (see Unknowns).

## Consumers: what the callers depend on

Census (executable-LOAD-segment E8/E9 scan, rel32 resolved, each
candidate Capstone-validated at the instruction boundary by linear
disassembly from its enclosing FDE start; reproduced by census.py and
re-run inside verify.py): **10 direct calls, 0 tail jumps, 4 distinct
caller FDEs** (0x5d18160, 0x5d1bf90, 0x5d1c4b0, 0x5d1e410 — the four
~0x370-byte loops of blst's windowed scalar multiplication), no stored
qwords and no relocations.

`caller_use.tsv` records, for every call site, the first instruction
that reads the returned window and the three that follow it:

| consumer | sites | first read | continuation |
|---|---|---|---|
| shift (window moved into the limb position) | 8 | `shl rax, cl` | `and rax, <mask>` within three instructions |
| mask-combine (window masked as the first use) | 2 | `and rax, [rbp-0x80]` | `mov rdx, rax` / `shr rdx, cl` |

**All 10 sites mask the window** before using it as a field. The
dependency is therefore: the window must place the requested field
exactly in its low bits, over the spanned bytes only, and the caller
masks and shifts it into place. A routine that leaked a byte beyond the
span, or that shifted by the wrong amount, would corrupt the recoded
window digit of the multiplication. The `and` continuations are the
observable contract, and they are what the committed ledger's `mask`
group isolates.

## Evidence notes

- main.txt is the raw `objdump -d` listing of the whole routine,
  verbatim instruction text (with the encoded bytes); the objdump
  symbol header is normalized to the bare binary name and the
  nearest-symbol annotations objdump adds to branch targets are
  dropped, so the file carries no machine-specific path and no
  misattributed symbol.
- frames.txt is the .eh_frame entry covering the routine
  (`pc=0000000005d0ed60..0000000005d0edb4`), read with `readelf -wf`.
- relocations.txt records the empty relocation set and both body
  hashes from the vendor census.
- cases.tsv is a **reviewable** 300-case ledger (75 per family under
  `boundary`, `shift`, `mask`, `random`), not a 1.6 MB blob. The
  exhaustive 2,400-case sweep and a 200,000-input differential are
  re-derived in memory by the tests and by verify.py; the committed
  ledger is asserted to be the generated subset.
- records.json holds semantic records (context, caller census,
  observations, unknowns, environment limits); instruction detail lives
  only in main.txt.
- verify.py re-checks the manifest, regenerates main.txt byte-for-byte
  and every instruction's bytes against the raw binary, regenerates both
  censuses, checks the FDE bounds and the census body hash, replays the
  committed ledger, and asserts the ledger is the generated subset.

Reproduce the excerpt:

    objdump -d --start-address=0x5d0ed60 --stop-address=0x5d0edb4 \
        artifacts/node/115/hl-node

## Unknowns

- What `nbits` means at the C level, given that the routine never masks
  to it. The observable behaviour is pinned; the crate-level argument
  name and intent are not.
- Fields spanning more than four bytes: the 32-bit loop would truncate
  them. Whether any caller ever asks for one is not established here --
  the call sites load `bitpos` and `nbits` from runtime values, not
  constants -- so the case stays uncharacterized.
- How each caller uses the masked field beyond the first two
  instructions (the consumer class and the mask are pinned; the full
  recoding dataflow is not).
- The body is byte-identical in 12 identical source objects
  (`identical_source_count` = 12); only address 0x5d0ed60 is bound.

## Environment limits

This work used static disassembly only (`objdump`/`readelf` on the
digest-verified local binary). No cargo/rustc, Ghidra or git-lfs was
needed, and the captured node was never executed. The model in
tools/get_wval_limb_5d0ed60_115.py is a Python transcription of the
pinned algorithm with an independently written literal transcription of
the same register dance, not a build of node or blst code.
