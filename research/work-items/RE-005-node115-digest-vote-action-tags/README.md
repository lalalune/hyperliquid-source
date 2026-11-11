# RE-005 · Node #115 distinguishes the two digest-vote Action tags

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The existing display-name packet covers a separate formatter arm. #4111 identifies selected vote payload writers. This packet recovers the outer Action selection that distinguishes the two 32-byte vote families before serialization.

Each of three formatter copies reads the leading Action qword and subtracts `0x86`. For `0xdc` and `0xdd` the subtraction has no borrow and `cmovae` selects the computed table index. The cells at indices 86 and 87 (decimal) are signed 32-bit displacements relative to the table base. Each selected case advances the payload pointer by 8, loads four name pointers and stages the forwarded serializer before calling its payload writer.

| Leading qword | Internal name literal | Named type literal | Payload writers in the three copies |
| --- | --- | --- | --- |
| `0xdc` | `VoteL1Hash` | `voteL1Hash` | `0x28fedf0`, `0x44b6060`, `0x5920730` |
| `0xdd` | `VoteAbciDigest` | `voteAbciDigest` | `0x29ab7b0`, `0x44c4ff0`, `0x5924bd0` |

Thus the observed names and payload targets distinguish the two variants consistently across all three copies. These internal qword values are dispatch discriminators. The evidence does not assign a numeric public wire tag or identify the digest algorithms, producer, or vote acceptance semantics. Only the six selected cells and arms are qualified. No component gate is requested.

## Reproduce

From the repository root:

```sh
packet=research/work-items/RE-005-node115-digest-vote-action-tags
python3 "$packet/verify.py" | diff - "$packet/dispatch.tsv"
objdump -d -M intel --insn-width=16 --start-address=0x2bc95f0 --stop-address=0x2bcbbe1 artifacts/node/115/hl-node
```

The verifier authenticates the ELF and indexed unwind extents, derives the linked table address and selected relative cells, resolves the name references and checks direct call targets. The TSV preserves six raw cell values. GNU objdump 2.45 was used to inspect instruction operands. No captured code was executed.
