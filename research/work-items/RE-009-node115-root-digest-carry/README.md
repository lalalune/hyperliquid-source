# RE-009 · Root digest parent carry

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The update path at 0x160b552 passes the context and its chunk counter to 0x160b0e0. This helper computes the counter's population count using the recorded SWAR masks and compares it with the existing 32-bit value-stack count at context +0x90. If the population count is at least the stack count the helper exits before merging.

For the selected valid merge path, each iteration removes the last two 32-byte values from the stack at +0x94, arranges the earlier value before the later value in a 64-byte input, and dispatches with the existing flags OR 4. It writes a 32-byte result over the earlier slot and publishes one less element than the iteration began with. Under normal helper returns and a valid initial stack, the loop exits when the new count reaches the selected counter's population count. The underflow guards, dispatch behavior and actual compressed bytes are outside the equivalence claim.

Run python3 research/work-items/RE-009-node115-root-digest-carry/verify.py from repository root. It validates the exact FDE, 16 byte witnesses, three selected edges and 196,608 synthetic checks of the derived bit-count arithmetic. No capture execution or digest-equivalence claim.
