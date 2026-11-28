# RE-009 — Node #115 stable quantity partition

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

After pivot selection, the ordinary quantity partition path at `0x4290b9d` uses scratch capacity of at least the active count. The scan takes rows in input order and writes keys strictly below the pivot to increasing scratch addresses. Equal and higher keys go to decreasing addresses. The pivot's own row is put on the latter side at its original scan position without going through the comparison. The low-side count increases only on a strict unsigned comparison. Both sides copy all 24 bytes per row.

The copy-back starts with a bulk copy of the low side. It then reads the high side backwards, two rows at a time with a one-row tail for odd counts. Both groups consequently preserve their own input order. This packet covers those two groups and copy-back. Pivot sampling and selection are described in #7555 and #7582.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-stable-partition/verify.py`.
