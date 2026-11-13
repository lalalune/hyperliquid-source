# Node #115 raw-map large rebuild run discovery

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is static analysis of the 24-byte record path, not a runtime trace.

The separately traced >=21-record rebuild path supplies the record count to `0x4f97450`. For `2 <= n < 4097`, instructions `0x4f974ad..0x4f974c3` compute `T = min(ceil(n/2), 64)`. For `n >= 4097`, let `k = ceil(floor(log2(n | 1))/2)`; `0x4f974ca..0x4f974ec` compute `T = floor((2^k + floor(n/2^k))/2)`.

At each discovered segment, `0x4f97580` computes the 24-byte-stride record address and compares remaining count to T. When at least T entries remain and at least two are available, `0x4f97610..0x4f97695` compares first-qword keys as unsigned: a nondecreasing initial pair enters a nondecreasing scan, while a strictly decreasing initial pair enters a strictly decreasing scan; scanning stops at the first opposing comparison or the available bound. The code also has separate short-remainder paths conditioned on the incoming flag. This finding does not claim full sort stability, final ordering, the outcome of later run merging, or real-world input distributions.

Reproduce with `python3 research/work-items/RE-017-node115-raw-map-sort-runs/verify.py`; the digest, instruction anchors and their mutations are checked without executing the target. `windows.txt` provides the disassembly.
