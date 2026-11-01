# Node #94 formatted-parts byte requests

This independently authored safe Rust implements the complete normal request and
callback-effect relation of `0x1572b20..0x1572da9`, 649 bytes / 169 instructions,
body SHA256 `8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3`.
Node #94 SHA256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The outer 602-byte padding routine is separate and is not implemented here.

The observed descriptor has prefix pointer/length and array pointer/count;
each part occupies three machine words. This API represents those values with
immutable raw word records and token-to-byte-view mapping. It does not identify
an original Rust enum, native pointer values, private ABI or header layout.

- Empty prefix skips its request and never resolves its unused view token.
- Full low-u16 tag0 reads word8 as a full u64 zero count. Zero0 skips every
  lookup/request; a positive run writes64-byte blocks and a final1..64 bytes.
  One method value is cached for that whole run; the next part reloads it.
- Tag1 reads only the u16 numeral at byte offset2 of word0 and emits its exact
  decimal ASCII bytes. The Rust performs its own quotient/remainder loop;
  no formatting API or opaque numeral helper constructs this payload.
- Every other full u16 tag requests the raw byte view selected by word8/word16,
  even if its length is zero. Bytes need not be UTF8.
- Every actual request outside a positive zero run loads the live method.
  Input data/table IDs stay fixed. Callback state/method changes persist.
  Every nonzero reply stops processing and returns1; complete success returns0.

Unvisited records/views/actions are not resolved, including those after an
earlier callback failure. Cases that make no requests need no method table.
Actually requested views (including empty ones) and reached method/action
targets must exist. The count must select a readable nonwrapping array prefix;
selected byte views are immutable, nonwrapping and at most isize::MAX bytes.

The domain is x86-64/usize64, immutable descriptor/parts/bytes/code/frame storage
separated from invalid writable aliases, and normal callbacks with ordinary call
preservation. Supplied callbacks can change live method cells and borrowed writer
state. Observer state is chosen callback state, not a native formatter header.
Pointers, stack-buffer retention, rendering, faults/unwind, concurrency, invalid
storage and original compiler/whole-node equivalence remain outside the claim.

No successful huge-u64 zero run is artificially capped. A decreasing remainder
proves theoretical termination; finite test cases use early failures where a full
successful trace would be impractical. The frozen finite corpus is supporting
evidence, not exhaustive part sequences or captured execution.

The independent v2 proof/corpus was sealed before this Rust: 69,359 distinct
eleven-field inputs, 90,453 callbacks and 73,214 exact RLE records, including all
65,536 u16 numerals. Freeze SHA256:
`2039b96fcd69aa4fe5e87d7e6478117d51958c7cfca2bd3684d4c3124c45bfe8`.
The earlier v1 and unpromoted insertion draft remain historical preparations.

The admitted published libcore's analogous helper is581 bytes, not649. No full
649-byte published candidate matched; that genuine negative result is retained.
No cropped/stiched comparison or compiled-window byte credit is claimed.

This source is uncompiled. The real no_std/core library and std input-only
client build directly using the audited research provider, without an invented
workspace/dependency graph. Actual scoped builds/controls, source/input/pin/
provider/linker guards and independent review must be recorded before publication.
Full suite/expanded evaluators, captured execution, hosted CI and full-node builds
remain NOT_RUN; all acceptance gates stay false. New source is project MIT work;
captured and upstream artifacts retain their rights. No unlicensed inferred
implementation was copied.
