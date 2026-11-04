# RE-001: bounded chain walk in node #115

- Component: RE-001 function map; the object and owning component remain unknown.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes).
- Base revision: `05bc2de303c05525b71e7e257426e741bc66a390`; no external source or reference revision is used.
- Question: given a starting node and a link budget, what does the complete function at `0x35bd510` return and store?

The function tests the unsigned 16-bit field at node offset `0x2ca` before checking the budget. If that field is nonzero, it writes four qwords `(0, current_node, remaining_budget, 0)` to the output. Otherwise, if the budget is zero it writes `(1, current_node, 0, 0)`. Otherwise it follows the pointer at `+0x2d0`, decrements the budget, and repeats. In both cases RAX returns the supplied output pointer. A nonzero field on the node reached by the final permitted link takes precedence over exhaustion. This rule assumes each visited pointer permits the indicated reads, output permits 32 bytes of writes, and output does not overlap the visited nodes. Invalid pointers and effects of aliasing are outside the claim.

## Evidence and interpretation

Original ELF virtual address range `0x35bd510..0x35bd563` is **83 bytes**, at file offset `0x35bc510`; its body SHA-256 is `fe0e202dcd84118b11e05556b15c5f564e78f18b78eb95c80cb9ffeb8fd595a9`. `records.json` contains its complete bytes and **22 instructions** with original bytes. The strict decoder consumes the entire body and checks the three branch displacements. The FDE at VA/file offset `0xddd718` has CIE `0xca6ed8`, augmentation `zR`, no LSDA, and describes exactly this range. The next FDE starts at `0x35bd570`; the intervening **13 padding bytes** are `cc`. These facts and both terminating paths support this particular extent; unwind records alone do not establish every function boundary.

The walk starts at `0x35bd513` with the field test. The nonzero branch at `0x35bd51b` reaches the output at `0x35bd539`; the zero branch tests RDX at `0x35bd520`. When nonzero, `0x35bd525` loads the successor and `0x35bd52c` decrements RDX before a fresh field test and back edge. The exhaustion arm at `0x35bd54f` zeroes both final words with `xorps`/`movups`. Both arms store the status last and return. The NOP is not a memory read. The field's domain meaning, node identity and original types are unresolved; labels here describe offsets and behavior only. There are **0 callees** and no indirect dispatch in the complete body.

An exhaustive bytewise scan for `e8`/`e9` rel32 encodings over `.text` `[0x1419300,0x63f0a00)` yields **1 direct-reference candidate**, at `0x3d6ec82` (`e8 89 e8 84 ff`), inside FDE `0x3d6e9d0..0x3d6edcd`. The preceding locally decoded instructions load RSI from `[rbp+8]`, test it for null, load RDX from `[rbp+0x10]`, set ECX to 1 and move R13 to RDI. The call is at a confirmed instruction boundary in this local context. This census includes accidental matches and does not cover indirect calls; it is not a reachability or complete caller proof. ECX is overwritten by the callee before use. No surrounding owner semantics are asserted.

## Novelty and reproducibility

Before investing in this candidate, both commands below returned no matches (exit status 1):

```sh
rg -i '35bd510|56349968' research/
rg -i '35bd510|56349968' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees to bind. This search checks address spellings, not all possible descriptions of the same behavior. The investigation used Python 3.13.5, GNU readelf and objdump 2.44 on Linux x86-64, with static disassembly and `readelf -wf`; neither captured program was executed. Regeneration and checks require only Python 3.10+ stdlib, the authenticated artifact and repository files. From the repository root:

```sh
python3 tools/node115_budgeted_chain.py --out research/work-items/RE-001-node115-budgeted-chain/
python3 -m unittest tests.test_node115_budgeted_chain -v
python3 research/work-items/RE-001-node115-budgeted-chain/verify.py
make verify
make catalogue-check
```

The tool hashes the complete input before producing output, checks ELF section geometry, the exact FDE/CIE and all instructions, checks the call target and scans the entire text. The records retain the complete body, unwind bytes and caller context without normalization. Tests cover the branch boundary, zero-budget precedence, looping links, full output and corruption of the digest, instruction, FDE and caller displacement. The model is independently authored from the decoded rule; it is not execution of the target.

## Limitations and next step

No reconstructed Rust, compiled comparison, original function name, component ownership, complete caller graph, data-layout identity, source provenance or whole-node equivalence is claimed. There is no source build, comparison mask, helper closure beyond this leaf, relocation/vtable closure or component gate. This is a bounded static result; it does not prove valid live object states or observable behavior under invalid memory. The caller's enclosing FDE and locally decoded call establish a context, not its full behavior. Next, trace the caller's node allocation and mutation sites to determine what the field and chain represent, with separate #115 evidence.
