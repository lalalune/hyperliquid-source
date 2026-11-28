# RE-009 — Node #115 quantity ordering parameters

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The large quantity ordering core at `0x3e73880` computes two parameters from the input count n. It rounds up the quotient of 2^62 divided by n by checking whether the division leaves a nonzero remainder. It stores the result at stack offset +0x78 and uses it to scale both run position expressions before XOR and bit scanning at `0x3e73b84`.

For n through 4096, the run-length threshold is min(64, ceil(n/2)). For n from 4097, let h be the highest set bit index and s be ceil(h/2). The threshold is floor(((n >> s) + 2^s)/2). The two paths publish the threshold at stack offset +0x20. The comparison at `0x3e739bd` uses it to select the natural-run scan when the remaining count is at least the threshold.

The run scan packet (#7551) covers the key comparisons and reversal. This packet verifies parameter setup and consumers. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-ordering-parameters/verify.py`.
