# Node #115 tracker demotion: iterator stop and 80-byte output

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence for the separately identified 31/32 tree-demotion builder.

`0x5b8e9b0` allocates up to 80 bytes per descriptor entry. On the selected normal loop, `0x5b8eae6` calls `0x51e32b0` with an iterator. A null returned node terminates output. Otherwise `0x5b8eaf9..0x5b8eb35` reads the selected qword key and 72 bytes of associated value from the node; it compares the first value qword against `0x8000000000000001` at `0x5b8eb3a`. Equality terminates before copying that row. For a non-sentinel value, `0x5b8eb3f..0x5b8eb76` writes key and value to an 80-byte output slot, increments output length, and advances to the next iterator result. At termination it stores the actual output length and returns the vector descriptor.

The observed stopping condition is not proof that the sentinel is a valid production value, that data is lost, or that the caller reaches this branch. This packet does not establish complete iterator ordering, allocator failures, or equivalence to live behavior.

Run `python3 research/work-items/RE-017-node115-tracker-demotion-stop/verify.py` for whole-target digest, byte and direct-call checks with anchor mutations; `windows.txt` provides disassembly. The captured target is not executed.
