# RE-009 — Node #115 quantity sort budget fallback

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The quantity partition helper `0x4290a90` sends counts up to 32 to `0x43b4e60`. For larger counts it checks the partition budget. A zero budget branches to `0x4290f13`, which passes the current row pointer, count, scratch pointer, capacity and caller context to `0x3e73880` with the fifth argument set to one. A nonzero budget proceeds to pivot selection and is decremented at `0x4290b56`.

This identifies the transition between the partition and large ordering helpers. The pivot selection and normal stable partition are described in #7555 and #7605. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-sort-budget-fallback/verify.py`.
