# RE-006: TWAP user ring lookup result

The advance and slice packets leave the search at `0x57f4ac0` open. In the selected nonwrapped representation, the search compares the leading 20 bytes of each 56-byte record with the caller's key through the memcmp import. With a strictly ordered valid ring, its second return register is the logical position relative to the head. The first register is zero for a match and one for a miss. On a miss the position is the insertion index, including the end. Empty input returns (1, 0).

For a nonempty ring, the candidate starts at index zero. Each iteration probes candidate plus half the remaining span. A positive comparison keeps the previous candidate, while zero or negative retains the probe. The span then loses that half. The final comparison returns the candidate on equality or adds one on a negative comparison. The selected caller tests the first return register at `0x4dc5bc9` before its separate miss/size path. This binds the search's result convention to the advance route covered by the prior TWAP evidence.

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Coordinates use ELF VA. Bounds assume valid pointers, no overflow in ring arithmetic and stable keys. Wrapped and tree representations remain open. No gate changes.

Run `PYTHONPATH=tools python3 -B research/work-items/RE-006-node115-twap-user-ring-search/verify.py` from the repository root. The independent sorted-list oracle compares the selected logical result with standard lower-bound arithmetic. It does not run or emulate the target.
