# Node #115: normalization before selected digest factor write

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the selected direct caller of `0x54cf1b0`, whose selector-3 factor write is studied in #6749.

After the selected helper returns tag `0x1a2`, `0x538d337..0x538d378` examines the magnitude bits of a binary64 input loaded from stack `+0x200`. A nonfinite value selects the pinned `1.0` literal at `0x4592b0`. A finite value instead selects `min(0.7, max(0.0, value))`, with the exact `0.7` encoding at `0x459a10`. This uses x86 `maxsd`/`minsd` behavior; no decimal source text or real-number precision is inferred. The selected result is passed in `xmm0` to `0x54cf1b0` at `0x538d39d`.

Independently, `0x538d378..0x538d398` checks the exponent bits of the binary64 value in `xmm1`; any infinity or NaN is replaced with the same `1.0` literal, while finite values are retained. The selector byte comes from stack `+0x18`. **If it is 3**, the conditional path in #6749 stores normalized `xmm0` into owner `+0x3e88`, then selects the producer which reads that factor. This packet does not establish that the selector is always 3, the external origin of either input, accepted protocol values, or behavior of other caller paths.

The relation requires the observed tag, normal returns and a successful selected allocation. Full configuration semantics, authentication, runtime reachability and replay correctness remain open; no component gate changes.

Run `python3 research/work-items/RE-017-node115-digest-factor-normalization/verify.py` for target digest, literal and instruction anchors, call target and corruption controls without executing the target. `windows.txt` contains the selected static windows.
