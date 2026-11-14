# RE-085: node 115 EMA short c54

This packet records the statically bounded FDE at `0x4d3e400–0x4d3e44a` in the pinned node 115 binary. The routine compares a length field, invokes a payload helper, and on equality advances both records by `0x18` before tail-jumping to the next comparator. This is static evidence only; no source reconstruction or behavioral equivalence is claimed.
