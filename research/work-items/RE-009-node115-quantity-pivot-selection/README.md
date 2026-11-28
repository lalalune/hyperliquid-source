# RE-009 — Node #115 quantity partition pivot selection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The ordering core's call at `0x3e73cc7` resolves through slot `0x64ea138` to `0x4290a90`.

The callee routes counts through 32 to `0x43b4e60`. On an iteration with nonzero partition budget and 33–63 rows, it sets q to floor(count/8) and selects the median unsigned key of rows 0, 4q and 7q. The instructions compare the three first qwords and select a row pointer. At counts of at least 64 it calls `0x43620e0` for the pointer. Both paths save the 16-byte prefix and final qword of the selected row, preserving a complete 24-byte pivot.

This evidence concerns pivot selection and capture. The subsequent partition moves are outside its scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-pivot-selection/verify.py`.
