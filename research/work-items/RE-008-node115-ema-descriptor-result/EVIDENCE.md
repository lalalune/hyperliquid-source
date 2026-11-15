# RE-008: selected descriptor and result effects of EMA query helper

- Component ID: `consensus` / RE-008.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream `main` `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference-source semantics imported.
- Claim status: instruction and edge observations; descriptor meaning beyond offsets is unresolved.
- Scope: one actual FDE and its selected entry, empty and writeback paths; no full CFG, helper closure, runtime execution, Rust implementation or gate advancement.

## Reproduce

From repository root: `python3 research/work-items/RE-008-node115-ema-descriptor-result/verify.py`. Input is the pinned `artifacts/node/115/hl-node`; Python standard library plus repository ELF/FDE readers. No target execution, networking, signing or side effects. Excerpts were produced with GNU objdump 2.47.20260726 using `-d -M intel` and the three exact VA ranges recorded in `excerpts.objdump.txt`; trailing whitespace removed; excerpt SHA-256 is `4bd5408878f849fca566ad4d9ea3d37445d04d9851b32ffb6e76a4e9cd5fd746`.

## Evidence

Coordinates are ELF VAs; `.text` starts at VA `0x1419300` and file offset `0x1418300`, so resolve via the section reader. The FDE at `0x1322010` covers `[0x514ef40,0x51506d0)`. Its full body has 6,032 bytes and SHA-256 `5c2fb47aef3e43bf495937434d561d8ae0e8e285f83cd4d56a5c912538669254`.

- `0x514ef54` loads old descriptor `+0x18`; `0x514ef60` clears it; `0x514ef6b` branches to `0x514f2a6` when the loaded value is zero.
- The zero-value block constructs `0x8000000000000001`, stores it at result `+0x08` at `0x514f2b3`, then returns the result pointer. Other result fields on this branch are not established.
- On a selected later path, `0x5150543` calls `0x4d30990`. At `0x5150558..0x515057c`, the function writes result `+0x30` and three 16-byte blocks covering `+0x00..+0x2f`. At `0x51505a1..0x51505a5`, it writes 24 bytes to descriptor `+0x18..+0x2f` and jumps to the return epilogue.
- The call's returned data and all branches between entry and this selected tail are outside this packet. The indirect call slots elsewhere in the FDE are not resolved here.

## Implementation and comparison

No Rust implementation or binary-equivalence comparison. The verifier checks original bytes, body identity and edge displacements, with five corrupted-byte controls. Passing these checks establishes only the selected static effects above.

## Results and limitations

The local verifier passes all 16 instruction witnesses, three edges and five controls against the pinned target. No component gate changes. Next question: determine the dataflow and reachable conditions for the `0x4d30990` call and the result object fields, including the remaining helper branches.
