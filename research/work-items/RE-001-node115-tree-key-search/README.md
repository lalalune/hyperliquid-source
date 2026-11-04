# RE-001: what does the node #115 tree-key search return?

Component: function map; a direct caller also contains a source-location reference associated with `l1/src/qtys/impl_ntl.rs`, but the callee's original name, ownership and domain meaning are unproved. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source revision: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86` is a reference, not recovered source. Status: binary observation and inference, no implementation or progress gate.

**Question.** Given a valid tree-shaped object and a pointer to a 64-bit query, how does `0x243ca40` select its return value?

**Answer.** With a null root, it returns zero without reading the query. Otherwise it compares the query as an unsigned 64-bit value against each node's keys in order, skipping keys strictly less than the query. Equality returns the address `node + 0x64`. If no key equals the query, it takes the child at the resulting insertion index while the remaining depth is nonzero; if the depth is zero, it returns zero. This describes the machine's traversal for valid readable nodes, query, and child pointers. Sorted keys make it an ordered lookup; sorting, node capacity, concrete types and domain meaning are not proved by this function.

## Evidence and derivation

The complete FDE range is ELF VA `0x243ca40..0x243cabb` (123 bytes; file offset `0x243ba40`), followed by 5 bytes of `cc` padding. SHA-256 of the unmasked body is `46b83804c37ee1e4667c35161e74896eb3d3f11f3b46bed08b5ad3a21b6e3bc0`. FDE file offset `0xd0f804` references CIE file offset `0xca6ed8`; its `zR` encoding gives a PC-relative signed 4-byte start and a 123-byte range, with no LSDA. At `0x28ce692` the first caller references Location `0x6432fa0`; its relocation points to `l1/src/qtys/impl_ntl.rs:6:1`. This association does not name the callee. The complete instruction walk and FDE/CIE bytes are in `records.json`; the generator checks every instruction's exact bytes and every local branch target. It records **35 instructions**, **0 callees**, and **2 candidate direct rel32 sites**. Both candidates are confirmed instruction-aligned calls by bounded independent disassembly: `0x28d37b2` in FDE `0x28cd7a0..0x28d8ac4`, and `0x2c49c8d` in FDE `0x2c47660..0x2c4d2e9`. These are all byte offsets across `.text` whose `e8`/`e9` and signed displacement target this entry; scanning arbitrary byte offsets overapproximates instructions and does not cover indirect calls, other executable sections or entries into the body.

- At entry the function loads root from `[rdi]`, depth from `[rdi+8]`, and query from `[rsi]` only when root is nonzero. It zeroes RAX for the absent result.
- For each node it reads a zero-extended 16-bit count at `node+0x62`, sets the key index to zero, and loads key `i` at `node+8+8*i`. The initial index register is -1; the addressing displacement `+0x10` and increment after each comparison implement that index.
- `cmp query,key; seta; sbb ... ,0` creates byte 1 for greater, 0 for equal and 255 for less. Only greater loops. Equality reaches `node+0x64`; less or exhaustion selects child index `i` or `count`, respectively. An unsigned borrow on `depth-1` returns zero; otherwise the next node is read at `node+0x68+8*index` and the loop restarts.
- No instruction calls, tail calls, writes to input memory or uses indirect dispatch. Each branch remains within this FDE and both returns are in it. The FDE is corroborated by the byte walk and padding, not treated as function proof on its own.

No normalization, masks, reconstructed Rust build or compiled-code comparison was used. An independent Python model covers the observed relation for valid node maps; its boundary vectors are derived from the instruction walk, not from executing the captured binary. Memory access faults, malformed pointers, invalid depth, overlapping fields and unsorted keys are outside the ordered-lookup claim. No claim is made about surrounding state, all callers, ownership, aliasing guarantees, value contents, complete component behavior or binary equivalence. No code was run from the capture.

## Reproduction and novelty

From repository root, Python 3.10+ stdlib; original ELF virtual addresses, Linux x86-64 target. The generator authenticates the complete input before producing files, decodes only the explicitly supported instructions and scans the complete stated `.text` range. Independent local exploration also used GNU objdump 2.44 and the repository FDE parser; neither is a generator or test dependency. The packet is entirely static and has no execution or network effects.

```sh
rg -i '243ca40|37997120' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
python3 tools/node115_tree_key_search.py --out research/work-items/RE-001-node115-tree-key-search/
python3 -m unittest tests.test_node115_tree_key_search -v
python3 research/work-items/RE-001-node115-tree-key-search/verify.py
make verify
make catalogue-check
```

Before creating this packet, the novelty search above returned no results. It now finds this packet by design. There are no callee addresses to check. Target identity, full decoded body, FDE, branch targets and caller census fail closed; focused controls mutate the real window and unwind/branch records as well as target identity. They do not establish behavior of invalid process memory or captured execution.

Next question: establish the caller's concrete node/value layout and sorted-key invariant from its construction and update paths before assigning a domain-level type or meaning to the returned address.
