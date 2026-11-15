# RE-001: node #115 TLS context producer relation

- Target: Linux x86-64 `hl-node` #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: what statically produces the `rsp+0xa0`/`rsp+0xa8` words consumed by
  the TLS-handle installation mapped in the related context-install packet?
- Scope: the two selected initialization branches in native FDE
  `0x15d6fd0..0x15d8447`; no execution, ABI recovery, or runtime reachability.

## Observations

Both branch copies load the same 16-byte source at `rsp+0x170` and store it at
`rsp+0xa0`. Therefore the two qwords later read at `rsp+0xa0` and `rsp+0xa8`
are a direct stack-to-stack copy of the helper-produced temporary at
`rsp+0x170`/`+0x178`:

- the first branch reaches the copy at `0x15d7047..0x15d708e` after the
  indirect helper call at `0x15d7026`;
- the second branch reaches the byte-identical copy at `0x15d70d6..0x15d711d`
  after the corresponding helper call at `0x15d70c2`.

The later installation reads those two qwords at `0x15d729f` and `0x15d72a7`,
then uses the second as the atomic-counter address at `0x15d72b9`. This packet
does not assign semantic names to the helper output, prove the helper's ABI, or
claim that every producer of these stack words has been found.

## Reproduction and limits

`verify.py` authenticates the complete ELF, checks the four exact instruction
windows against the selected FDE, and verifies the retained objdump excerpt.
The captured binary is not executed or emulated. The remaining question is the
callee's own write contract and the producer of its input at `rsp+0x510`.

