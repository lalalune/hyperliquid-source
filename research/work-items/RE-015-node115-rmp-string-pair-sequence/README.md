# RE-015 — Node #115 MessagePack sequence of fixed string pairs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [pair-vector packet](../RE-015-rmp-pair-vec-115/) covers a separate pair path with an optional string and leaves this body at `0x22755b0` open.

The selected sequence path reads the element count for the outer array header. Each 48-byte row emits another array header with count 2. It then supplies the first pointer and length at row +8 and +0x10 to the string writer `0x25e8750`. The second pointer and length come from +0x20 and +0x28. In this path both values are written as strings. The caller tests for return word 2 after the inner header and each string.

The pre-loop row path and recurring loop use separate call sites with the same header and string writer targets. The loop advances the source pointer by 0x30 only after both fields pass the success checks. This establishes the ordinary fixed-pair layout and its write order. Large-count handling, error ownership and the alternate output mode remain outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-015-node115-rmp-string-pair-sequence/verify.py` from the repository root for static instruction and call-target checks.
