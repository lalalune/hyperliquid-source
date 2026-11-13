# RE-008: shared Date sequence visitor

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the sequence visitor `0x376e720` identified by open #6598, whose element path that PR explicitly leaves outside scope. It does not execute target code.

## Selected observations

- At entry the visitor reads a 32-bit value from the input descriptor `+0x08`, chooses the smaller of that value and `0xaaaa`, and uses 24 times that number for the initial allocation. This is an initial allocation bound, not proof that accepted sequence length is capped at `0xaaaa`. A zero input takes the empty `{0, 8, 0}` buffer path.
- The loop calls `0x31f91f0` with a pointer from the input descriptor and a zero third argument. A result byte other than `9` takes the error-copy path at `0x376e890`. On tag `9`, the selected path reads a 32-bit result word and 20 further bytes. A zero result word branches to finalization. A nonzero result is appended as a 24-byte element after capacity handling, and the visitor advances its input count.
- Finalization passes the local three-word buffer descriptor to `0x3cbbef0`. When the helper returns the sentinel `0x8000000000000001`, the caller passes the 13-byte string `duplicate key` to `0x30466c0` and takes its error return. Otherwise it copies the helper result into the caller's output and returns the other status. This establishes the selected error-message branch, not the helper's sorting, key-comparison algorithm or the precise duplicate relation.
- The full retained disassembly covers FDE interval `0x376e720..0x376e93f`, verified with `readelf -wf`. An FDE is not proof of complete function ownership, full CFG coverage or actual runtime reachability.

The labels “input count”, “element” and “buffer” are inferences from observed layout and #6598's context. The body and error format of `0x31f91f0`, the semantics of its 24-byte result, input framing, allocation failure, comparison internals and equivalence to the map visitor are not established. No node reconstruction gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-008-node115-date-sequence-visitor/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=000000000376e720'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x376e720 --stop-address=0x376e93f artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks eleven selected byte/string anchors and three direct-call targets, and rejects eleven single-byte anchor mutations. It does not prove all function instructions, runtime behavior, helper contracts or all caller paths. No captured code is executed.
