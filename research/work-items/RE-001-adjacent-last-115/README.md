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

## Independent implementation and reproduction

The new `src/node115-adjacent-last/lib.rs` is safe `no_std` Rust with no
allocation/dependencies. It returns an owned length coordinate and preserves
all old-length backing rows, including inactive tail bytes. It follows the
observed copy/swap schedule rather than using a generic dedup operation.
This library is new; main previously supplied the static packet but no Rust
for this complete transformation. The original packet and captures are intact.

Native expectations were Git-sealed at
`3b7e035c0b44e441c609a2f711fc37ad5e57653e` before Rust source existed.
The corpus has3,373 distinct raw byte inputs: all three-key sequences through
length7 plus length32 runs/nonadjacent repeats, identical rows and one-bit
changes at all32 record-byte positions. No input-specific callback supplies
answers. Expected outputs come from actual instructions with complete RETs.
308/312 body bytes and73/74 starts are visited; the only remainder is an
unreachable4-byte alignment NOP. This is a behavioral state relation, not a
registered target-byte match or a complete consensus implementation.

```sh
python3 research/work-items/RE-001-adjacent-last-115/verify-rust.py \
  --rustc /path/to/rustc \
  --out /fresh/output/directory
```

The runner SHA-checks/decompresses its published Rust fixture, builds original
source at opt0 and opt3, compares every sealed row, checks byte-identical
same-path opt3 rlib/output repetition, and compiles12 deliberate wrong sources.
Each wrong source must emit a complete3,373-row stream with changed results
and fail the independently sealed client assertions with ordinary exit101;
crashes or incomplete output are not accepted as successful controls.
`rust-results.json` reports actual mismatches; full receipts, full comparison
streams and command stdout/stderr are losslessly archived. Only the owned
workspace path prefix is projected to `<work>` in command-output archive.

The140 selected client cases only reuse sealed rows. They include full-tail
assertions: replacing distinct copies with swaps or duplicate swaps with copies
can leave the logical prefix correct while violating the complete state.
See VALIDATION.md for actual results, failures and check scope. No model calls,
original ELF execution, target compiler recipe or Linux build is claimed.
