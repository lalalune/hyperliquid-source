# RE-001: one additional TokenSpec writer caller

- Component: serialization; one bounded static RE-001 caller question.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Independent stdlib static parsing and GNU objdump, no target execution/emulation.
- No implementation, whole-schema, registration-policy or completion-gate claim.

## Gap and observation

Integrated `RE-015-rmp-seq-newtype-115/bodies.tsv` records wrapper `0x41a4ea0`
using `0x3c44290` as its direct element helper but explicitly excludes element
serializer bodies. Open PR6576 at head
`c383ac30c2f903f207a7f5d40057f9cf38521be1` studies writer `0x3c453f0`
and the registration tail; it explicitly leaves this other caller unexamined.
This packet adds only a concrete caller input/handoff, not either earlier result.

Actual FDE `0xe53b24` and its CIE establish `[0x3c44290,0x3c446c4)` (1076 bytes).
The body hash is retained but it is not a full semantic analysis. One 436-byte
entry/handoff excerpt is retained, with raw bytes, instruction boundaries and
unwind records in `discovery.json`; there are no normalized comparisons.

At entry, incoming RDX is saved in R15 and RSI in R14. At `0x3c443ed`,
RSI becomes R14+0x30, RDI becomes current RSP, and RDX becomes R15.
The aligned direct call `0x3c443f7` (`e8f40f0000`) reaches `0x3c453f0`.
Thus this writer receives a nested object at incoming RSI+0x30, the same saved
serializer pointer, and stack-local output storage. The nearby conditional
name-mode arm references four bytes `spec` at VA `0x45a1e4` before this call.
The immediate post-call result-head comparison branches to `0x3c445f4`
on nonmatch. That destination and full error ownership are not analysed here.
Register-flow interpretation assumes the usual callee-saved-register convention
at the intervening calls; no runtime behavior or public ABI is established.
`TokenSpec` is a contextual role label from PR6576, not a recovered Rust type.

## Reproduce and controls

From repository root:

```sh
python3 research/work-items/RE-001-node115-tokenspec-extra-caller/verify_target.py --with-objdump
python3 -m unittest discover -s tests -p test_node115_tokenspec_extra_caller.py -v
```

The verifier checks full digest before any native tool. It maps ELF sections,
locates the unwind-index entry, checks actual FDE/CIE records, decodes the extent,
checks body/excerpt bytes and selected instruction operands, then optionally
cross-checks the contiguous excerpt with GNU objdump. Discovery used GNU
binutils 2.40; cumulative discovery timing is recorded in `discovery.json`.
A single retained entry/handoff excerpt replaces the exploratory window.
Controls mutate every bit of selected operand/opcode groups in a private
bytearray, plus digest, FDE pin and field literal. These are evidence-integrity
controls, not behavioral equivalence or tests of a reconstructed serializer.

## Results and limits

Actual execution results are retained separately in `local-proof.json`.
The local proof predates independent validation; independent check results are
reported in the PR and controller validation record. No hosted-CI or full-suite
pass is claimed here. Imported binary bytes retain upstream rights; newly authored code
and documentation use the repository MIT terms. There is no whole-component
function denominator, Rust implementation, source-built node, helper closure,
network/chain operation, signing or paid dataset. All gates stay false.

Next: close the containing object layout and remaining field/helper error paths
before reconstructing its serializer; those are outside this bounded packet.
