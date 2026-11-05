# RE-001: map node115 UTF-8 validation shared by startup inputs

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The shell-output adapter and node configuration input use a shared validator at 0x16815e0. The validator has a 16-byte ASCII fast path guarded by an alignment test, a length bound, and the high-bit mask across two adjacent qwords. High-bit leads index the retained width table; branches separately restrict E0, ED, F0 and F4 second bytes. Bounds checks precede each continuation read.

Success stores tag zero and the original pointer and length. Failure stores tag one and the start offset of the sequence. A missing continuation clears the error-length presence byte, while malformed data sets it and stores the error length within that sequence, from one to three. The length payload byte is unspecified when absent. This closes the converter result boundary previously referenced by the shell adapter and config path.

The retained 1 full FDEs cover 503 bytes and 143 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-utf8-result-115/collect.py --out work/startup-utf8-result-fresh
python3 -B research/work-items/RE-001-startup-utf8-result-115/verify.py --out work/startup-utf8-result-check-fresh.json
```
