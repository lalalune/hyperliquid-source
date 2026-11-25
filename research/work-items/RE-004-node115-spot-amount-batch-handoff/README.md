## RE-004: node #115 spot-amount conversion to batched records

This packet advances the open [#3908](https://github.com/lalalune/hyperliquid-source/issues/3908) assets and fixed-point quantities reconstruction by connecting the existing spot amount conversion caller to a batch-record producer and its vector consumer. It documents a bounded static relation, not a completed asset or quantity gate.

## Target and task boundary

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4`.
- Component: RE-004 quantities and rounding; issue #3908.
- Coordinates below are ELF virtual addresses.
- Existing evidence at `RE-004-node115-spot-amount-caller` binds the conversion leaf to source fields and an accepted result. Existing `RE-004-order-value-gate-115` explicitly leaves the caller's use of that result open. This packet examines that use at one selected call path.

## Observations

1. In caller `0x2c2e230..0x2c2e7d2`, the code calls the order-value gate at `0x2c2e5b6`, checks its result tag against `0x1a2` at `0x2c2e5bb`, and branches away on a different tag at `0x2c2e5c2`. The success path calls `0x22e81c0` at `0x2c2e5db`.
2. Function `0x22e81c0..0x22e8382` stages a vector header and argument record, calls `0x2d36860` at `0x22e82a9`, then passes the staged vector to consumer `0x241a3c0` at `0x22e82ca`.
3. Producer `0x2d36860..0x2d3764c` calls the existing conversion caller `0x22e5090` at `0x2d36a84`. It checks the returned tag at `0x2d36a89` and reads the result's `+8` qword at `0x2d36a9c`, followed by a range check.
4. The producer calls through slot `0x64e0f78` at `0x2d36bb3`. The ELF RELATIVE relocation resolves this slot to `0x162a9a0`. At `0x162aa93..0x162aaa1`, the helper writes the output's dwords at `+0` and `+4`, and its qword at `+8`; consequently, the earlier conversion quotient is not shown to survive unchanged in this same output slot.
5. The producer writes tag `4` into a record at `rsp+0x210`, computes a record span using stride `0x2c8`, copies the record into the growable vector supplied through input `+0x70`, and increments the vector length.
6. Consumer `0x241a3c0..0x241b097` reads the three-word vector header, resets it, derives the record span using `count * 0x2c8`, checks a record discriminator (including a special comparison with `0xb`), and dispatches through an indirect call.

These are instruction and dataflow observations. They establish a selected status-gated path from the order-value result into a conversion-producing batch builder and onward to a batch consumer. They do not establish the business meaning of tag `4`, the discriminator values, or the record fields.

## Inferences and unresolved questions

- Inference: the selected path uses an accepted order-value result to enter the batch builder, because the success-tag branch immediately precedes the call. The verifier checks the call sites and bytes; it does not model every path condition in the full caller.
- The `+8` qword read is observed as a conversion result field. Since a later helper rewrites that output area, this packet does **not** claim the quotient is copied unchanged into the appended record.
- The wire decoder and original input format, amount units, semantic record names, the relationship between the converted value and later record fields, and downstream effects remain unresolved.
- No captured binary was executed or emulated. No component-level acceptance gate is marked complete.

## Evidence and reproduction

`verify.py` authenticates the target SHA-256, derives the seven FDE extents from `.eh_frame`, checks 25 exact instruction-byte witnesses (including the indirect call and helper output writes), checks five direct-call destinations, and resolves the relocation at `0x64e0f78`. It also flips each witnessed byte in-memory and confirms that all 25 witness mutations are rejected. This validates the encoded evidence checks, not semantic completeness or runtime behavior.

From the repository root:

```sh
python3 research/work-items/RE-004-node115-spot-amount-batch-handoff/verify.py
python3 -m unittest tests.test_spot_amount_batch_handoff_115 -v
```

Expected verifier summary: 7 FDE extents, 25 instruction witnesses, 5 direct-call edges, relocation `0x64e0f78 -> 0x162a9a0`, 25 rejected witness mutations, and `captured_binary_executed: false`. The unit test also confirms refusal when the target digest is changed.
