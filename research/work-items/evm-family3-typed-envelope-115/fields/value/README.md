# EVM value-field adapter: key gate and numeric tail ABI

Component `evm`, subordinate to the merged family-3 envelope evidence.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x5b69430..0x5b69486`: 86 bytes / 29 instructions.

The payload writers pass value storage in R8 and the `value` key pointer/length
in RDX/RCX. Entry RDI=output and RSI=buffer. This resolves the adapter contract
left opaque in those callers; the numeric encoder itself remains outside scope.

At `0x5b6943b`, mode byte buffer+0x1b is tested against zero. Any nonzero mode
calls `0x57cf5d0` with buffer/key/length. Only RAX=2 continues. Another RAX
writes output discriminator 0x8000000000000000 and copies RAX/RDX to +8/+0x10.
Mode zero bypasses key writing and its result gate.

Continuation preserves the original output RDI, sets RSI to the original R8
value pointer and RDX to buffer, restores saved registers, then tail-jumps at
`0x5b69466` to actual FDE start `0x4fb2b40`. The adapter performs no local
numeric conversion, payload copy or allocation. This is an argument/dataflow
observation, not a claim about the tail encoder's output or Rust type.

```sh
python3 research/work-items/evm-family3-typed-envelope-115/fields/value/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full digest/FDE, complete decoding,
instruction pins, branch boundaries and external tail are checked. Eight
operative mutations reject below image SHA guard; 1,280 conditional mode/key
result cases pass. Complete bytes and FDE/CIE/call/branch records are retained.
No captured instructions execute or are interpreted.

Valid stable nonaliasing pointers and normal helper returns are assumptions.
Numeric/key encoding, allocator behavior, exceptional paths and full native-tool
suite remain unqualified. No gates change. Next: recover the byte-input
adapter's additional representation flag and buffer-copy ownership.
