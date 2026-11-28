# RE-014 — Existing-value replacement in the node #115 funding-rate map

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The funding-rate caller packet identifies calls at `0x54aa031` and `0x54b6a71` to `0x4dcf640`. Existing source-location evidence for `0x4dcfa32` binds the helper to a location in `base/l1_map/entry.rs`.

The helper saves the input value from XMM0 and the key from RSI. In the selected flat hit path, `0x57f8260` supplies an even RAX hit tag and logical index in RDX. The helper checks that index against length at +0x18 and adds the head at +0x10, subtracting capacity when the sum reaches capacity. The value address is the buffer at +8 plus 16 times the physical index plus 8. The selected tree hit also reaches the shared replacement tail at `0x4dcf9a6`.

That tail loads the previous value into XMM0, stores the saved input value from XMM1 to the same slot, and returns tag 1 in EAX. The slot transfer is bit-preserving through the scalar moves. This covers replacement on the hit paths. Insertion, map conversion and ownership of the container beyond the observed callers remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-014-node115-funding-rate-map-update/verify.py`. It reads the pinned artifact and checks instruction bytes, direct edges and synthetic flat-ring addresses.
