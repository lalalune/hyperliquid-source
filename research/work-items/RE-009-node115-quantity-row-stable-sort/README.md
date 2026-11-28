# RE-009 — Node #115 quantity row insertion sort

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The ring-to-tree packet #7496 identifies the short ordering call but leaves the callee opaque.

The converter calls `0x53eea20` for row counts 2–20 with a sorted-prefix length of 1. The helper uses 24-byte rows and compares their first qwords as unsigned values. When a row key is less than its immediate predecessor, it saves the current key and 16-byte payload, shifts larger preceding rows one slot to the right, and writes the complete saved row in the gap. Equal keys retain their relative order because equality ends the backward search and skips the first shift on adjacent equality.

This binds the order of the rows entering the quantity-tree builder. The large-count ordering routine and tree builder remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-row-stable-sort/verify.py` for static instructions and bounded synthetic row-order checks.
