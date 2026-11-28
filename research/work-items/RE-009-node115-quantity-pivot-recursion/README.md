# RE-009 — Node #115 recursive quantity pivot sampling

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The quantity partitioner switches to `0x43620e0` at 64 rows. It supplies three row bases at indices 0, 4q and 7q, where q is floor(count/8). In the helper, the normal recursive branch divides the current span by eight. It then samples offsets 0, 4s and 7s from each of the three supplied row bases, with s equal to the reduced span. For the 24-byte quantity row this yields byte offsets 0, 96s and 168s. The helper passes s to each recursive call and takes a median of the three returned row pointers, using their unsigned first qwords. The base case compares the three supplied rows directly. The returned value is always a pointer into the sampled rows.

The preceding partition-pivot packet (#7555) identifies the direct 33–63-row case and callee address. This packet covers recursive sampling for the larger case. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-pivot-recursion/verify.py`.
