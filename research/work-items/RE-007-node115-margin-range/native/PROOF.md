# Conditional flat tier range and predecessor

New explanation is MIT; capture and retained native output keep their original rights. This packet uses node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. Addresses below are ELF virtual addresses, not runtime addresses. No captured code was executed, emulated or interpreted.

## Scope and premises

The selected bodies are included-upper-bound `0x4550ee0..0x4550fc4` (228 bytes / 75 instructions) and range wrapper `0x3cd80d0..0x3cd8292` (450 bytes / 135 instructions): **678 bytes / 210 rows** of evidence, not newly measured coverage or a compiled-code comparison. Full GNU exports, FDE text and raw FDE/CIE records are retained. `BINDINGS.json` pins every byte and describes the selected direct call; `PORTABILITY.json` records the two header-only path replacements. No instruction row was normalized.

The operation starts with actual supplied flat rows, not a supplied predecessor or lookup callback. Header words are capacity C at +0, backing data D at +8, head H at +16 and live length L at +24. Native row stride is 40; key is u64 at row+0, c is u64 at row+24 and b is a byte at row+32. The projection preserves all other row bytes. **b=0 is accepted:** no margin division or scalar formula is implemented here.

Require stable valid header, query, borrowed row storage and local/output frames; output frames must not alias the header, query or rows. Active spans and one-past endpoints must be addressable, with nonwrapping native pointer/stride arithmetic. Exclude the tree representation, whose first header word is exactly `0x8000000000000000` (`0x3cd8134..0x3cd813d`). For the canonical safe view, L<=C, H<C for nonempty backing, and H=L=0 for empty backing. Checking canonical H when L=0 is stricter host policy: the native empty helper ignores H. Only live logical keys must be unsigned nondecreasing; equality and arbitrary inactive bytes are allowed.

Logical row i is physical H+i when i<C-H, otherwise i-(C-H). A safe implementation can use this split without overflowing H+i. N spans the entire u64 query domain. No higher caller's signed magnitude restriction is imposed on this helper.

## Included upper bound

Let U be the count of live logical keys <=N. For L=0, the helper returns zero without dereferencing rows; it still reads the header data word while forming the empty expression.

For L>0, let F=min(L,C-H), R=L-F. When R=0 the helper searches the first segment. Otherwise `0x4550f0e..0x4550f11` tests the first key of the second segment. If it is <=N, sortedness makes the whole first segment eligible: search the second and add F. If it is >N, no second-segment key qualifies: search the first.

Each segment loop tests base+floor(length/2). CMOVA at `0x4550f64` or `0x4550fa4` retains the old base only for key>N; equality advances it. Length becomes ceil(length/2). The last eligible position remains within the shrinking interval if one exists; otherwise base stays zero. At length one, CMP/SBB at `0x4550f75..0x4550f79` or `0x4550fb5..0x4550fb9` adds one iff the candidate is <=N. This yields the segment's upper-bound count. The wrapped one-element fast path returns F+1 after the known qualifying first-key test.

Consequently duplicates, including a run crossing the seam, select the **last logical** eligible occurrence. The exact-seam immediate-equality rule of the separate RPC exact-key operation does not apply. U is always within [0,L] under these premises.

## Actual range and consumer binding

Credited #2223 caller exports at base `05bc2de303c05525b71e7e257426e741bc66a390` are retained in [first margin leaf](../../RE-007-node115-position-margin-paths/38b54b0.objdump.txt) and [second margin leaf](../../RE-007-node115-position-margin-paths/38b5300.objdump.txt). Their complete hashes and extents are in `BINDINGS.json`; these are context, not additional selected-body credit or an arithmetic implementation.

Both obtain the table pointer from object+16, construct lower tag 2 (unbounded), upper tag 0 (included), upper payload N, and call the wrapper at `0x38b54dd` / `0x38b532d`. The unused lower payload is not read on this tag path. The wrapper chooses start zero at `0x3cd81a7` and the actual included-upper helper at `0x3cd81e8`. Lower-bound and tree helpers are not reached. U<=L makes the bounds-diagnostic call at `0x3cd828c` unreachable for the admitted path; its RELATIVE binding is retained without claiming callee semantics.

For U>0, A=min(U,C-H), and the wrapper writes tag 1 followed by two half-open spans:

```
[D + 40*H, D + 40*(H+A))
[D,        D + 40*(U-A))
```

For U=0, both native spans are [D,D), independently of H. The safe API chooses two borrowed `rows[0..0]` slices and no predecessor. Its optional/index representation is a new safe observation, not a native ABI or a recovered error enum.

The first leaf tests the second span at `0x38b5520..0x38b552a`, then the first at `0x38b552c..0x38b5536`; the second leaf does likewise at `0x38b536f..0x38b5385`. The last endpoint minus one 40-byte stride identifies logical U-1. Thus end-16 and end-8 read c and b at row+24/+32. A returned row's key follows from this selected row identity; the leaves do not themselves reread it.

For no predecessor, the downstream leaves enter opaque diagnostic routes. The first diagnostic at `0x38b55eb` is followed by UD2; the second at `0x38b5460` is followed by the overflow continuation if the callee returns. Do not generalize a trap/nonreturn theorem for both or claim that the margin leaves return None. The valid wrapper's empty range and the safe API's absence value are distinct from those downstream effects.

## Static reproduction and limits

`verify_static.py` reads the authenticated capture only as data. It uses Python's standard library, no subprocess, project imports, numerical model or instruction interpreter. With an existing fresh output parent:

```sh
python3 -I -B -S research/work-items/RE-007-node115-margin-range/native/verify_static.py \
  --target artifacts/node/115/hl-node --out /absolute/fresh/margin-static-result
```

The helper checks full target identity, selected ELF mappings, all retained exported bytes, raw FDE/CIE identities and PC extents, selected direct-call encoding/target and the bounds-diagnostic relocation. This draft records no execution result; later actual qualification belongs in the packet's validation record. Identity checking is not a behavioral oracle or semantic corruption-control result.

The table's original construction/global content, tree path, generic lower/upper modes, arithmetic in either margin leaf, diagnostic/unwind effects, lifetime/concurrency guarantees and financial units remain outside this operation. #2223's formulas and open arithmetic work are prior credit, not a scope to duplicate. One capture lineage and finite future source tests cannot establish whole-node equivalence or advance a full component gate.
