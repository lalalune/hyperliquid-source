# RE-067: node115 EMA short c36

Static evidence packet for FDE `[0x4d3b5c0, 0x4d3b7b8)` (504 bytes), `.eh_frame` offset `0xf1725c`, from the pinned node115 artifact.

The range is a comparator over two records. It first compares the `+0x50` pair through the shared indirect comparator, then performs sentinel-aware scalar checks over the remaining byte fields, with early exits back to the common signed-result epilogue. This is a static mapping of bytes and unwind ownership only; it makes no execution or ABI-equivalence claim.
