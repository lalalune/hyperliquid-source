# Node94 ASCII three-byte equality

`equal(length: u64, left: &[u8; 3], right: &[u8; 3]) -> bool` projects
the complete numeric return at node94 ELF VA `0x151a4a0..0x151a52f`.
Only a raw length of three is admitted to the comparison. ASCII uppercase
letters fold to lowercase; all other byte values compare unchanged.

This is a dependency-free `no_std` safe Rust library with fixed snapshots.
Native pointer validity, faults, concurrent input changes and original ABI
are outside its scope. The [evidence packet](../../research/work-items/RE-004-ascii-three-rust-94/README.md)
contains the complete proof, frozen oracle and actual compiler commands.
