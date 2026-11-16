# RE-001: what the tree branch of `0x3f19f10` stores next to the id

- Component: token-id registry; one bounded static RE-001 question.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `a8a165e65d53abc1c996bcc9b609749529cfc41a`.
- Independent stdlib static parsing and GNU objdump, no target execution/emulation.
- No implementation, whole-container, registration-policy or completion-gate claim.

## Gap and observation

`research/work-items/RE-005-node115-token-id-derivation/README.md` models the
token-id registry only as key membership (`BTreeSet`) and states explicitly
that "the tree branch of `0x3f19f10` was not traced; only key membership is
modelled". Its next question asks "what the tree branch of `0x3f19f10` stores
next to the id". This packet answers exactly that question and nothing else.

Actual FDEs and their CIEs establish five functions: insert `0x3f19f10`
(141 bytes), tree insert `0x3706900` (286 bytes), recursive tree insert
`0x34f9d60` (2843 bytes), value-address `0x3f1a750` (99 bytes), lookup
`0x3cd39b0` (1055 bytes). Body hashes are retained but are not a full semantic
analysis. Seven excerpts are retained, with raw bytes, instruction boundaries
and unwind records in `discovery.json`; there are no normalized comparisons.

At `0x3f19f10`, `cmp [rsi],0; je` dispatches on the position struct's tag:
zero takes the flat path, nonzero takes the tree path. The tree path copies a
48-byte position struct and calls tree insert `0x3706900`, which saves the
incoming index in R15 and, for a null root, allocates a 0x118-byte node
(`malloc` via slot `0x64df480`), clears `+0xb0` and the u16 count at `+0x112`,
bounds the slot at 11 (`cmp rcx,0xb; jae`), stores the 16-byte key from
position struct `+0x08` at node+slot*16, and stores the index at
node+0xb8+slot*8. The recursive insert `0x34f9d60` does the same at its common
store `0x34f9e56` (`mov [r13+rax*8+0xb8],rcx`, rcx the incoming index), with
the same 11-slot bound and count at `+0x112`.

The value-address function `0x3f1a750`, called right after insert with the
24-byte result, independently confirms the layout: the tree case returns
node+0xb8+slot*8, the flat case returns flat entry+0x10 (24-byte entries,
ring-buffer index math). The lookup `0x3cd39b0` confirms the key provenance:
its vacant path stores the 16-byte id at insert-struct+0x08 (the bytes the
tree branch copies into the node), and its conversion path stores the id at
insert-struct+0x18 with a zero at +0x08 — the zero that makes `0x3f19f10`
take the flat path.

**Result: the tree branch stores the incoming index beside the 16-byte token
id — the same (key, value) pair the flat branch stores (incoming rdx at
entry+0x10) — so the two storage forms are value-consistent.** Not claimed:
a full container model, flat-key provenance beyond the offsets above, the
`rax==1` condition at `0x3cd3b9d` (observed, not interpreted), the `0x3f1a750`
abort path, any Rust crate change, or any completion-gate change.
`TokenSpec`/`token id` are contextual role labels from RE-005, not recovered
Rust types.

## Reproduce and controls

From repository root:

```sh
python3 research/work-items/RE-001-node115-tokenid-tree-value/verify_target.py --with-objdump
python3 -m unittest discover -s tests -p test_node115_tokenid_tree_value.py -v
```

The verifier checks full digest before any native tool. It maps ELF sections,
locates the unwind-index entries, checks actual FDE/CIE records, decodes the
extents, checks body/excerpt bytes and selected instruction operands, then
optionally cross-checks the contiguous excerpts with GNU objdump (172 decoded
instructions). Discovery used GNU binutils 2.42; capstone is not installed in
this environment, so objdump is the only cross-check. Controls mutate every
bit of the pinned semantic instructions in a private bytearray, plus digest
and FDE pin corruption. These are evidence-integrity controls, not behavioral
equivalence or tests of a reconstructed registry.

## Results and limits

Actual execution results are retained separately in `local-proof.json`.
The local proof predates independent validation; independent check results are
reported in the PR and controller validation record. No hosted-CI or full-suite
pass is claimed here. Imported binary bytes retain upstream rights; newly authored code
and documentation use the repository MIT terms. There is no whole-component
function denominator, Rust implementation, source-built node, helper closure,
network/chain operation, signing or paid dataset. All gates stay false.

Next: the remaining RE-005 questions — what the three request generators pass
in the 0x78-byte request, where the state word `+0x28` is incremented, and what
the two other callers of the `TokenSpec` writer do with it; those are outside
this bounded packet.
