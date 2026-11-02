# Node94 alias-aware indexed table offset

`apply` reconstructs the returned u64 and optional four-byte output store at
node94 ELF VA `0x54ccfb0..0x54cd009`. It uses one bounded mutable byte image,
explicit runtime addresses, the input base value and raw index. The original
low32 index, null object/output rules and unsigned table entry are preserved.
The output store precedes the table read, including exact/partial aliases.

`table_base` must represent the original LEA result (linked VA 0x5799cc0 plus
the actual load bias). Table contents and length are runtime inputs, not file
constants. Address/image bounds are checked before any mutation; errors are
new atomic safe refusals rather than native fault behavior. Code/control-state
overlaps, concurrency/MMIO and original ABI are outside the correspondence.

This is a dependency-free safe `no_std` library compiled directly with rustc.
The [evidence packet](../../research/work-items/RE-004-table-offset-alias-rust-94/README.md)
contains the complete proof, frozen expectations, native driver and build recipe.
