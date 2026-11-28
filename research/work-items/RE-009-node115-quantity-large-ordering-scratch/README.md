# RE-009 — Node #115 quantity ordering scratch storage

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The quantity ring-to-tree converter (#7496) hands counts of at least 21 to the indirect call at `0x516b775`. The slot `0x64e5368` resolves to `0x36e5360` through a relative relocation.

For row count n, the wrapper computes ceil(n/2), capped at 333,333 rows. It uses 4,096 bytes of local scratch with a reported capacity of 170 rows when the computed count fits. Otherwise it requests 24 bytes per computed row on the heap and releases that buffer after the sort core returns. The call to `0x3e73880` receives the input rows and count, scratch pointer and row capacity, a flag for n < 65, and the caller context.

The packet covers normal scratch selection and handoff. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-large-ordering-scratch/verify.py`.
