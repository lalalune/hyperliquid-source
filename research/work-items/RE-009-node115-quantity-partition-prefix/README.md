# RE-009 — Node #115 quantity partition prefix

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The quantity partitioner switches to `0x4290d70` when its prior-bound key is at least the current pivot or an ordinary strict-lower pass returns zero rows. Unlike the ordinary strict-lower branch documented in #7605, this path compares pivot against row and places keys less than or equal to the pivot in the first group. It puts the selected pivot itself in that first group. Keys above the pivot go to the end of scratch and are read back in reverse scratch order.

After copying the prefix back, the helper computes the remaining count by subtracting the prefix length. A zero remaining count exits. Otherwise it advances the active row base past the prefix, restores the higher group in input order, clears the prior bound and continues sorting only that group. With a valid pivot lower bound, the prefix consists entirely of equal keys.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-partition-prefix/verify.py` to check the instructions and synthetic bounded partition cases.
