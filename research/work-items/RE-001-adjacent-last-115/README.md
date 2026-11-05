# RE-001: reconstruct exact last-record compaction, including backing tail

Consensus / node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Complete leaf
`0x5b2d510..0x5b2d648`; all coordinates are ELF VAs. Merged static #2525
and `RE-001-node115-adjacent-key-last` establish the byte walk and key role;
this work adds actual-instruction expectations and independent Rust state
comparison rather than another address map or coverage-only test packet.

Read [the frozen contract](CONTRACT.md). The leaf keeps the last32-byte row
of each adjacent run with equal leading20 bytes. Nonadjacent duplicates stay
separate. Equality ignores the trailing12 payload bytes, but moves the complete
record. Initial/later duplicate steps swap, while distinct steps copy. The
old-length backing tail is retained in the comparator, not hidden by the new
logical length. A first-wins dedup or a correct visible prefix with a different
tail does not satisfy this relation.

```sh
python3 research/work-items/RE-001-adjacent-last-115/proof.py --objdump "$(command -v objdump)"
python3 -m unittest discover -s tests -p test_adjacent_last115.py -v
```

`native.py` evaluates every actual supported leaf instruction and real RETs;
there are no helper callbacks or assumed calls. Packet-local SIMD semantics
are needed to compare the actual20-byte key. Shared tools are untouched.
`proof.py` authenticates complete target/FDE/CIE, GNU/Capstone bytes, branch
targets and the actual caller/source binding. COW changes alter actual bytes,
not a hand-written expected function. Expectations must be Git-sealed before
Rust. The one unreachable4-byte NOP is exported but not visited.

Scope is valid disjoint writable bounded storage and normal return, not
original ABI, full record type, caller ordering, global uniqueness, fault/
unwind behavior or consensus validity. No captured ELF process, Unicorn or
live service is used; no signing/chain/wallet action is performed. New source
and docs are independently authored MIT; no inferred unlicensed source is read
or copied. Captures, old packet, imports and all92 gates are preserved. Next
question: close the caller's input construction/order before assigning protocol
meaning or composing this local transformation into consensus delivery.
