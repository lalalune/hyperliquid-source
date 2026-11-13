# Node #115: selected decimal-to-binary64 scale-zero path

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the conversion helper behind the second stage of the selected factor parser in #6751. It complements the independently documented reverse f64-to-decimal conversion in `l1-shared-f64-to-decimal-115` and does not claim full conversion equivalence.

Pinned slot `0x64e4e68` resolves to `0x5c44b40`. It reads flags dword at input `+0`, high magnitude dword at `+4` and low magnitude qword at `+8`. When bits `16..23` of flags are zero, `0x5c44b7a..0x5c44b97` forms a two-word integer: it negates the low qword and subtracts borrow from the high word if the flags' sign bit is set; otherwise it retains the original zero-extended magnitude. It passes the resulting pair through slot `0x64e1888`, whose pinned relocation resolves to `0x63f0160`, and returns result tag 1 with the binary64 in `xmm0`. A zero magnitude enters this conversion as integer zero regardless of the sign flag.

The helper window at `0x63f0160..0x63f0207` uses the input high-word sign, computes a two-word magnitude, locates the highest set bit and builds a binary64 word with rounding-related bit operations. This supports its selected signed-integer conversion role, but this packet does not independently establish every rounding boundary or calling convention for all callers. Scale-nonzero paths, alternate decimal encodings, the full parser grammar and factor authority remain open. Do not interpret this static result as target execution or whole-node equivalence.

Run `python3 research/work-items/RE-017-node115-digest-decimal-scale-zero/verify.py` for target digest, selected instruction anchors and mutation controls. Static windows and relocations are in `windows.txt`.

## Prior coverage

Merged `RE-008-node115-fee-trial-source` also includes this helper, with a short-decimal implementation and fixtures limited to a bounded domain (scale up to 16). This packet isolates a selected static path and does not replace that implementation or establish complete conversion equivalence.
