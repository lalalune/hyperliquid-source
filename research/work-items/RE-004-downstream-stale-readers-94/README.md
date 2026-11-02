# RE-004 downstream stale readers — node #94

## Claim status

**Claimed.** #169's Next question — do downstream readers consume the
stale fields installed by the four direct verbatim paths? — is answered
by a complete census of the 11 direct call sites of the four
gate-pattern callers, in 9 caller FDEs:

- **Yes, in the orchestrator (3 of 3 trioA call sites).** Whenever
  trioA takes its verbatim path, the orchestrator's read block reads
  both stale spans of trioA's output buffer ([obj+0x1..0x8] and
  [obj+0x11..0x20], 22 bytes) and copies them into the orchestrator's
  own output object ([rbx+0x9..0x10] and [rbx+0x19..0x28]), which it
  then returns from. The residue is not merely installed: it is read
  and propagated into a live output object.
- **No, in the other 8 call sites** (5 double-gate, 2 trioB, 1
  gate-like): no instruction in the caller FDE reads a stale offset of
  the verbatim destination object. Details per site in
  `reader-sites.tsv`.

**Not claimed.** No downstream impact beyond the orchestrator's output
object is claimed: whether the orchestrator's caller reads
[rbx+0x9..0x10] / [rbx+0x19..0x28] is a further census, left as the
Next question. No defect, exploitability, or security severity is
claimed. Indirect (vtable) callers of the four gate-pattern callers
are not enumerated; the census covers direct `E8` call sites only.

## Scope

Included:

- 11 direct call sites: trioA × 3 (all in the orchestrator
  `0x4e6fef0..0x4e713bd`), double-gate × 5, trioB × 2, gate-like × 1.
- 9 caller FDEs (orchestrator + 5 double-gate callers + 2 trioB
  callers + 1 gate-like caller), each read in full.
- 3 orchestrator read blocks (`0x4e700fc`, `0x4e70827`, `0x4e70f21`):
  14 stale-span load instructions and 14 propagation store
  instructions, byte-anchored in `segments.txt`.
- 6 propagation span mappings in `propagation.tsv` (3 call sites × 2
  stale spans): 7 bytes → `[rbx+0x9..0x10]`, 15 bytes →
  `[rbx+0x19..0x28]`, 22 bytes per call site.
- 46 byte segments in `segments.txt` (39 claim segments, 211 bytes:
  11 calls + 14 reads + 14 stores; 7 anchor segments, 23 bytes: trioA's
  verbatim stores, #169's claim re-cited with attribution).

Excluded:

- The orchestrator's tag == 5 paths (sentinel compare, constructor
  installs): on those paths the orchestrator does not execute the
  read blocks, and the buffer is constructor-filled before any copy.
- The shared read blocks' non-trioA edges: `0x4e700fc` is also
  reachable via a decoder-A re-decode edge (`0x4e6ffdf`) and
  `0x4e70827` via a decoder-A edge (`0x4e705f2`). Those edges read
  the same instructions but their buffer provenance is not
  trioA-verbatim; they are excluded from the 3-site read verdict and
  reported here only as shared-block notes.
- Indirect/vtable callers of trioA, double-gate, trioB, gate-like.
- Readers of the orchestrator's output object after it returns.
- The #157–#169 subjects and #1543's fixed-eight topic. #169's
  staleness verdicts are cited, not re-claimed; the trioA verbatim
  store instructions are anchors (`kind=anchor` in `segments.txt`).

## Observations

### The census: 11 call sites, 9 caller FDEs

Direct `E8` call sites were found by scanning `.text` for `E8` +
rel32 == target − (va + 5), then mapped to enclosing FDEs via
`.eh_frame` ranges. Every call site falls inside exactly one FDE.

| caller FDE | callee | call VA | dest object | verdict |
|---|---|---|---|---|
| orchestrator `0x4e6fef0..0x4e713bd` | trioA | `0x4e6ff83` | rdi = `[rsp+0xe0]` local buffer | READ → `0x4e700fc` |
| orchestrator | trioA | `0x4e707b9` | rdi = `[rsp+0xe0]` local buffer | READ → `0x4e70827` |
| orchestrator | trioA | `0x4e70e2a` | rdi = `[rsp+0xe0]` local buffer | READ → `0x4e70f21` |
| dg1 `0x4e64730..0x4e64d9e` | double-gate | `0x4e64a0b` | rdi = r14 = entry rsi | NO-READ |
| dg2 `0x4e65140..0x4e656e4` | double-gate | `0x4e653e8` | rdi = r14 = entry rsi | NO-READ |
| dg3 `0x4e66660..0x4e6680c` | double-gate | `0x4e66671` | rdi = entry rsi (arg-shifted) | NO-READ |
| dg4 `0x4e66810..0x4e66f9b` | double-gate | `0x4e66baa` | rdi = rbx = entry rsi | NO-READ |
| dg5 `0x4e67d30..0x4e6839f` | double-gate | `0x4e68040` | rdi = rbx = entry rsi | NO-READ |
| tb1 `0x4e69150..0x4e69425` | trioB | `0x4e6927c` | D = decoder-derived (trioB r14) | NO-READ |
| tb2 `0x4e69580..0x4e696ff` | trioB | `0x4e6961b` | D = decoder-derived (trioB r14) | NO-READ |
| gl1 `0x4e69430..0x4e69573` | gate-like | `0x4e694cb` | D = decoder-derived (gate-like r14) | NO-READ |

### The orchestrator reads: 3 of 3, both spans, 22 bytes each

All three trioA calls pass the same buffer (`rdi = [rsp+0xe0]`) and
the same tag-check shape: after the call, the orchestrator reads
`[rsp+0xe0]`, compares to 5, and on `jne` jumps straight to its read
block. No instruction between the call return and the read block
writes to the buffer, and trioA's verbatim path writes the full
`[rdi+0x0..0x20]` (stores at `0x4e6fe0c..0x4e6fe34`, anchored). So on
the verbatim route the read blocks provably consume trioA's verbatim
bytes, including both stale spans:

- Span 1, `[obj+0x1..0x8]` (7 bytes): block 1 reads it byte-wise
  (`0x4e700fc/0x4e70104/0x4e7010c` + dword `0x4e70114`) and stores it
  to `[rbx+0x9..0x10]` (`0x4e7014f/0x4e70152/0x4e70155/0x4e70159`);
  blocks 2 and 3 read it as dwords (`0x4e70827/0x4e7082e`,
  `0x4e70f21/0x4e70f28`) and store to the same output span
  (`0x4e70838/0x4e70835`, `0x4e70f32/0x4e70f2f`).
- Span 2, `[obj+0x11..0x20]` (15 bytes): all three blocks read it as
  qwords (`[rsp+0xf1]` and `[rsp+0xf8]`) and store to
  `[rbx+0x19]` and `[rbx+0x20]` — union `[rbx+0x19..0x28]`
  (the `[rbx+0x20]` store overwrites the last byte of the
  `[rbx+0x19]` qword; both source qwords are stale-span bytes, so
  the union is 15 stale bytes).
- The blocks also copy the decoder-written fields (`[rsp+0xe0]` tag →
  `[rbx+0x8]`, `[rsp+0xe8]` pointer → `[rbx+0x10]`, `[rsp+0xf0]` flag →
  `[rbx+0x18]`) and set the header `[rbx] = 4`; the function then
  returns with the residue in its rdi output object (`rbx = rdi` at
  `0x4e6ff04`).

### The no-read sites: 8 of 8, with reasons

- **dg1, dg2:** the dest register (r14 = entry rsi) is never
  dereferenced anywhere in the caller FDE. The dest object is
  dropped after the call.
- **dg3:** the dest pointer (entry rsi) is not retained after the
  call; rsi is reused for size arithmetic and later call arguments.
- **dg4, dg5:** the dest object (entry rsi) IS read post-call, but
  only through the saved-rsi alias rcx (`[rsp+0x18]`) at offsets
  `0x80`, `0x90`, `0x1e0`, `0x1f3` — never at the stale offsets
  `0xb9..0xc0` or `0xc9..0xd8`. (rbx itself, which held the dest at
  the call, is never dereferenced in either FDE.)
- **tb1, tb2, gl1:** the verbatim destination D is decoder-derived
  and never available to the caller: the caller holds only its rdi
  object (`[rsp+0x80]`, `[rsp+0x48]`, `[rsp+0xf]` respectively), and
  every post-call read targets that rdi object (tag byte at
  `[rdi+0x20]` plus the table/vtable-fill region) — never D.

### Shared-block note (excluded from the verdict)

The read blocks are shared code: `0x4e700fc` is also reachable from
the decoder-A re-decode edge (`0x4e6ffdf`, after trioA's tag == 5
path), and `0x4e70827` from a decoder-A edge (`0x4e705f2`). On
those edges the buffer was not written by trioA's verbatim path —
neither trioA's tag == 5 path (which writes only `[rbx+0x0]`,
`[rbx+0x8]`, `[rbx+0x10]`) nor decoder-A (3 fields) nor the
orchestrator before call 1 (zero stores to `[rsp+0xe0..0x100]`
before `0x4e6ff83`) writes the overhang spans — so the same
instructions there consume older frame residue, not #169's bytes.
The packet's read verdict rests only on the three direct trioA-call
edges, where the buffer provenance is trioA-verbatim.

## Inferences (separated from observations)

- The stale bytes are observable, not merely installed: at least one
  direct caller (the orchestrator, on all three of its trioA sites)
  reads both stale spans and copies them into its own output
  object, which survives the orchestrator's return.
- The shape is caller-specific, not a property of the verbatim copy
  itself: 8 of 11 direct callers never touch the stale bytes, and
  the orchestrator's read blocks consume the buffer overhang
  unconditionally (on the decoder-A edges they read whatever the
  frame held). A reader census must therefore be per-caller, not
  per-shape.

## Limitations

- Direct `E8` call sites only. A vtable/indirect caller of trioA,
  double-gate, trioB or gate-like would not appear in this census;
  none was found by the direct-call scan, but indirect reachability
  is not disproven.
- The orchestrator's caller is not censused: whether anyone reads
  `[rbx+0x9..0x10]` / `[rbx+0x19..0x28]` of the orchestrator's
  output object after it returns is the Next question.
- The no-read verdicts are FDE-scoped: a dest object that escapes
  its caller FDE (e.g. dg1/dg2's entry-rsi object, which belongs to
  the caller's caller) could be read elsewhere; no such read is
  claimed or excluded here.
- Static analysis only; no node execution, so no runtime values of
  any stale byte are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (verified: the
recorded instruction bytes match the binary at those offsets, and
the generator fails loudly on any mismatch).

```sh
# orchestrator read block 1 (call 1's non-tag-5 target)
objdump -d -M intel --start-address=0x4e700fc --stop-address=0x4e7017c \
  artifacts/node/94/hl-node
# orchestrator read blocks 2 and 3
objdump -d -M intel --start-address=0x4e70827 --stop-address=0x4e7086d \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e70f21 --stop-address=0x4e70f67 \
  artifacts/node/94/hl-node
# trioA verbatim stores (anchors)
objdump -d -M intel --start-address=0x4e6fe04 --stop-address=0x4e6fe37 \
  artifacts/node/94/hl-node
python3 tools/downstream_stale_readers.py --out /tmp/ds-readers
diff -r /tmp/ds-readers research/work-items/RE-004-downstream-stale-readers-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/downstream_stale_readers.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/downstream_stale_readers.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

The generator reads only `artifacts/node/94/hl-node`, checks its
SHA-256 and size first, writes only to `--out`, and performs no
execution, evaluation, disassembly or network access.

## Next question

- Does the orchestrator's caller read `[rdi+0x9..0x10]` /
  `[rdi+0x19..0x28]` of the orchestrator's output object — i.e. does
  the propagated residue survive one more call boundary, or is it
  overwritten before any read? That needs a caller census over the
  orchestrator's direct callers, symmetric to this one.
- Which runtime path fills the orchestrator's `[rsp+0xe0..0x100]`
  overhang on the decoder-A edges — and does any caller read the
  orchestrator's output object on those routes?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — 11 call sites, 9 caller FDEs, 3 read blocks,
  6 propagation mappings, segment inventory
- `reader-sites.tsv` — 11 rows, one per direct call site
- `propagation.tsv` — 6 rows, one per (call site × stale span)
- `segments.txt` — 46 rows: 11 call + 14 read + 14 store claim
  segments (211 bytes) + 7 trioA verbatim-store anchors (23 bytes),
  each with start..end, length == end − start, and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
