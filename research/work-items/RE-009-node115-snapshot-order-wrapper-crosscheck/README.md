# RE-009: compare two snapshot order wrapper bodies

The selected wrapper in #7163 and the independently documented wrapper in RE-012-snapshot-order-record-dispatch-115 have matching instruction bytes across paired 710-byte windows once thirteen explicitly named displacement fields are compared by destination. Eleven fields resolve to the same addresses. The two remaining fields are the direct variant tail jump and the wrapped variant value call. Both resolve to 0x25dd560 in the first wrapper and to 0x23f6ec0 in the sibling.

This comparison allows a shared framing implementation to preserve the differing value encoders. It covers 658 unmasked bytes in each wrapper and checks all thirteen operand fields separately. The two value encoders are outside the comparison. The windows use pinned ELF virtual addresses. Run the command in offline-log.txt from the repository root. The check reads binary bytes only.
