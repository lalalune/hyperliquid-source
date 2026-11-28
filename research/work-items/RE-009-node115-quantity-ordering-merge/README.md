# RE-009 — Node #115 quantity ordering merge

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Inside the large quantity ordering core, `0x3e73d52` checks two run lengths before merging. Zero-length inputs or scratch capacity below the smaller length branch around this path.

The code copies the shorter run to scratch using 24 bytes per row. On equal lengths it copies the left run. With the left run copied, the forward loop takes a row from the right only when its unsigned key is strictly smaller. With the right run copied, the backward loop takes a row from the left only when its key is strictly larger. Both loops therefore place left rows before right rows on equal keys. Each iteration moves the full 24-byte row and advances only the input cursor for the chosen row.

The packet covers scratch selection and the two merge loops. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-ordering-merge/verify.py` to verify the captured instructions and synthetic merge fixtures.
