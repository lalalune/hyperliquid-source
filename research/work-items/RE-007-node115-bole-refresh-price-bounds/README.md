# RE-007 — Node #115 borrow/lend refresh price bounds

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The selected caller window starts at the sample median call established in #7411. A zero returned word branches away from the store covered here.

The caller first reads the bound at record +0x30. A nonzero bound replaces the selected word when `binary64(selected) / binary64(bound) - 1.0 < 0.0`. It then reads +0x38 and, when nonzero, replaces the intermediate word when the corresponding ratio minus one is greater than zero. The second comparison sees the first comparison's selected word. At `0x369afcb` the caller writes the resulting integer word to record +0x10.

The two conversions use low and high 32-bit lanes with separate binary64 biases. The compare constant at `0x458dc8` decodes to −1.0. Because the comparisons use binary64, adjacent integers above the exact-integer range can compare equal and preserve the input word. For example, the lower-bound test preserves 2^53 against 2^53+1. Zero bound words skip their respective checks.

The packet covers this compare-and-store sequence. It leaves the provenance of the bound words and later record processing open. Run `PYTHONPATH=tools python3 research/work-items/RE-007-node115-bole-refresh-price-bounds/verify.py` at the repository root for static instruction checks and binary64 model cases.
