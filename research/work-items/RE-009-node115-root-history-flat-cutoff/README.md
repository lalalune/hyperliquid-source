# RE-009 · Flat root-history cutoff

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The flat removal arm calls 0x57f2d30 at 0x4de5b8d. With valid metadata, the callee uses capacity, start index and count to split a ring into up to two physically contiguous spans. It compares the first key of the wrapped span, if present, against the cutoff. If that key is strictly lower, it adds the whole first span to a search within the wrapped span. Otherwise it searches the first span. The comparison at both binary-search boundaries is unsigned and strict, so keys equal to the cutoff do not contribute. Each row is 40 bytes with its comparison key in the first qword.

The caller subtracts the returned count from the current count and scales by 40 to prepare the survivor allocation. This defines the selected flat path's cutoff and size computation. It assumes the logical ring is ordered and the two slices and key pointer are valid. Subsequent copies, exact retained history after publication, tree removal, and runtime reachability remain open.

Run python3 research/work-items/RE-009-node115-root-history-flat-cutoff/verify.py from repository root. It validates the selected FDE and direct edge, pins 15 instructions and compares the derived search with linear counting for 18,315 synthetic cases, including duplicate keys, wrapped spans and unsigned boundaries.
