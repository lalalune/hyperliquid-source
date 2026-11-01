# Node94 highest-bit table lookup

`lookup(value: u128, table: &[u64; 128]) -> u64` reconstructs the
returned value of node94 ELF VA `0x55442e0..0x554431b`. Value zero returns
zero; otherwise the most significant set bit selects one of 128 table words.
The u128 packs the original low/high fields at offsets 0x1488/0x1490;
the table represents the original words beginning at offset 0x1088.

This dependency-free `no_std` library uses safe Rust and admits every value
and table bit pattern. It assumes stable ordinary input snapshots, without
reconstructing pointer faults, volatile reads or original ABI. The
[evidence packet](../../research/work-items/RE-004-bsr-table-rust-94/README.md)
contains the complete layout/priority proof and native reproduction commands.
