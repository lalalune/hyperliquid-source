# RE-003: bin supply of the node #115 priority-prefix byte-fed entries

- Component: serialization/foundation, delayed-action configuration — the
  caller side of the byte-fed entrypoints certified by
  `RE-003-node115-priority-prefix`.
- Target: node **#115**, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Bounded question: which caller supplies the three byte-fed
  `PriorityRateDelayParams` entrypoints, from what input form, and under
  what length and representation conditions?
- Observation/proof: each entry has **exactly one direct caller in the
  whole `.text`**, a dedicated MessagePack decoder FDE per
  monomorphization. The decoder slices a **bin payload** (markers
  `0xc4`/`0xc5`/`0xc6`), requires the reader to hold the full declared
  length, wraps the payload in a fresh `{cursor, end, count = 0}` state
  and calls the entry with its own output struct as the destination. It
  performs no post-call inspection of the entry's output or consumed
  count, and imposes no payload-length cap of its own.
- No full decoder, concrete Rust type, live API, delay policy or
  reconstruction gate is claimed.

## Why this item, in one paragraph

The operator action is a delayed-action configuration reaching the node in
MessagePack form, with the delay parameters carried as one bin field. The
basis for the expected behaviour is the merged `RE-003-node115-priority-prefix`
packet, which certified the entries' three-byte normal path and left the
explicit next question "which caller supplies this byte-fed interface, and
which typed input path establishes the semantic names/types of its optional
suffix?" The loss if this stays unrecorded: a reimplementation can supply
the entry from the wrong representation — decoding the parameters
element-by-element, capping the bin at three or six bytes, or treating a
short payload as a partial read — and every one of those silently
diverges, because the actual contract (any declared length the message
carries, a fixed error record when the payload is short, the consumed
count never checked) is recorded nowhere. The item is independent of the
nearest open RE-003 PRs by repro case, not just by filename: #2329 is a
protocol-design document with no binary trace, and #2393/#2075/#2062 are
robustness fixes to the `priority_prefix_static` checker tool; none of
them produces or alters this caller trace.

## Evidence identity and completeness

| Role | FDE half-open VA range | Bytes | Retention |
| --- | --- | ---: | --- |
| entry A (boundary, owned by RE-003 prefix packet) | `0x1839480..0x1839913` | 1,171 | hash + frames; export lives in the owning packet |
| entry B (boundary) | `0x2fbf570..0x2fbfa03` | 1,171 | hash + frames |
| entry C (boundary) | `0x48117a0..0x4811c33` | 1,171 | hash + frames |
| caller A | `0x1a63db0..0x1a6559d` | 6,125 | hash + pinned windows |
| caller B | `0x33210f0..0x33228dd` | 6,125 | hash + pinned windows |
| caller C | `0x4adf150..0x4ae093d` | 6,125 | hash + pinned windows |
| parent A (boundary) | `0x19271c0..0x19292b3` | 8,435 | hash + call-site pins |
| parent B (boundary) | `0x32e15c0..0x32e36b3` | 8,435 | hash + call-site pins |
| parent C (boundary) | `0x4b76720..0x4b78813` | 8,435 | hash + call-site pins |

The measured denominator is **nine complete FDEs, 47,193 bytes**. The
three callers and three parents exceed the 4 KB export bound, so they are
retained as body hashes plus byte-pinned trace windows — the same
treatment the RE-015 packet gives its large consumer — and every pinned
site is validated as a native instruction start during generation. The
entries' body hashes are re-derived here and match the owning packet's
`records.json` values exactly; their exports are not duplicated.
`records.json` retains body hashes, file offsets and actual FDE/CIE raw
bytes for all nine; `frames.txt` contains independent GNU readelf
confirmations. No normalization mask is applied.

## Census

- One pass over `.text` E8 rel32 calls: each entry has exactly **1**
  direct call site, inside its caller (`caller+0xe8a` in every case);
  each caller has exactly **2** direct call sites, both inside its
  parent FDE.
- `.rela.dyn`: **zero** addends name any of the nine FDE starts; **zero**
  raw 8-byte occurrences of any start exist in the capture. The wiring
  is direct-call only.

## The supply path, stage by stage

All offsets below are relative to a caller FDE start; the three callers
are byte-identical at every pinned window (the only address-dependent
bytes in the traced region — the dispatch LEA target, the entry-call
displacement and the alternate-call displacement — are checked
relationally per caller).

1. **Marker dispatch.** The decoder's first byte goes through a 256-entry
   relative jump table (caller A table `0x5375e4`, B `0x739460`,
   C `0x8ab3ac`). Decoded landings: marker `0xc4` (bin8) → guard at
   `+0xc05`, `0xc5` (bin16) → `+0xb4b`, `0xc6` (bin32) → `+0xb2c`. Each
   of the three guards is the landing of exactly that one marker, and no
   marker lands on the join, tail, state build, error block, alternate
   block or epilogue.
2. **Length routes.** bin8 consumes a 1-byte length after a nonzero
   remaining test; bin16/bin32 first require remaining ≥ 2 / ≥ 4 (else
   the shared short block consumes the rest of the reader and leaves the
   call unreached), then read the big-endian length (`rol`/`bswap`). The
   header sizes 1/2/4 are read back out of the pinned guard bytes.
3. **Shared tail** (join `+0xc1b`, tail `+0xe54`). With payload start
   `p`, length `L` and post-header remaining `r`: `r - L` is computed;
   on borrow the tail branches to the error block (stage 4). Otherwise
   the reader cursor advances to `p + L`, remaining becomes `r - L`,
   and `dl` is tested.
4. **Boundary error record.** On a short payload the caller writes tag
   byte `1` at out `+0x8` and the qword `0x2500000003` at out `+0x10`,
   then reaches the common error tail at `+0x1649`, which writes qword
   `2` at out `+0x0` and returns the output struct. The byte-fed entry
   is not called.
5. **The `dl` split.** With `dl == 0` the caller builds the entry state
   on its stack at `[rsp+0x20]`: `{p, p + L, 0}` — cursor, end, and a
   count cell initialized to zero — passes it as RSI with RDI = the
   caller's own output struct, and calls the entry. The next instruction
   after the call jumps straight to the epilogue (`mov rax, rbx; … ret`):
   the entry's writes to the output struct are the caller's result, and
   neither the output tag nor the final count is read. With `dl != 0`
   the same slice `(out, p, L)` goes to an alternate slice decoder
   (caller A `0x2b87440`, B `0x3b9c8a0`, C `0x54552c0`) instead, with the
   same immediate return.
6. **Parent wiring.** Each decoder's parent FDE calls it from exactly
   two sites; at every site the five bytes before the call are
   `4c 89 f6 31 d2` (`mov rsi, r14` / `xor edx, edx`), so the decoder is
   always entered with `rdx = 0`. No `dl`-writing instruction sits on
   the jump-table path between decoder entry and the bin guards.

## Result summary

For a bin marker with post-marker remaining `r` and declared length `L`:
`r < header` never reaches the tail; `r - header < L` yields the error
record `{+0x0: 2, +0x8: 1, +0x10: 0x2500000003}` and no call; otherwise
the payload slice is supplied to the byte-fed entry with a fresh
zero-count state (the `dl == 0` route) or to the alternate slice decoder
(the `dl != 0` route), and the decoder returns at once. The checker
carries this contract as `supply_route()` and the tests assert it over
the boundary grid for all three markers. As wired — both parent call
sites passing `rdx = 0` — the entry route is the taken one.

## Explicit boundary and next question

What could set `dl` nonzero is **not** established by these bytes: the
alternate route is present and pinned, but no enabling input is
identified, and the alternate slice decoders themselves are not traced.
The decoder's second entry path (the peeked-marker state at reader
`+0x20/+0x21`) and the marker taxonomy beyond the three bin markers are
not traced. What the entry does with payload bytes past its certified
three-byte prefix — the merged packet's optional-suffix question —
remains open: this packet establishes only that the caller caps nothing
and checks nothing after the call. The parents' own input provenance
(which message fields reach the two call sites) and any semantic type
name beyond the merged packet's diagnostic label are not established.
No gate is claimed.

Next question: which input, if any, reaches the bin supply with
`dl != 0` — and what does the alternate slice decoder (`0x2b87440` for
caller A) make of the same payload?

## Reproduce and validation

From repository root with the materialized pinned capture and native GNU
tools on PATH:

```sh
python3 -B tools/priority_prefix_caller_static.py --output research/work-items/RE-003-node115-priority-prefix-caller
python3 -B -m unittest discover -s tests -p test_priority_prefix_caller_static.py -v
(cd research/work-items/RE-003-node115-priority-prefix-caller && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot. During
generation the checker additionally parses each caller's native export
and asserts the complete direct-branch edge set into the pinned blocks
(join ← bin32 jump only; tail ← join jump only; state build ← no branch,
fallthrough only; error ← tail borrow branch only; alternate ← tail
`dl` branch only; epilogue ← the eight recorded return jumps, including
the post-call and alternate jumps). Wrong-release, truncated and
same-size modified public inputs are rejected before output creation.

Focused controls alter the actual entry-call displacement, the
error-record immediate, the `dl` branch opcode, a jump-table landing,
the parent `xor edx, edx`, an entry body byte and an FDE record; each
makes the checker reject the counterfactual. Below the full public
digest gate, this checks the named obligations, not arbitrary-byte
error detection or target execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and all
progress gates are preserved. No hosted-CI result or whole-component
completion is claimed.
