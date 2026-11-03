# Frozen Node115 reader relation, before Rust implementation

RE-005 / serialization. Source base8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Target a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
All addresses are unrebased ELF virtual addresses. Six FDE extents,1807 bytes,
512 instruction-byte pairs. FDE extents do not prove source function boundaries.

Domain: canonical mode qword0 or1; valid, disjoint input/state/output storage,
nonwrapping pointers, little-endian wrappers. Raw arbitrary modes, padding and
aliasing are excluded. A safe Rust interface will use logical types, NOT the
original ABI. P is input pointer,N remaining,C charged count,L limit.
Only active result fields are defined. No original enum/type/version claim.

Scalar copies2cd7ac0 and5821250: mode1 first checked-add8 toC. Overflow returns
rawtag2 retainingC; otherwise storeC+8 BEFORE comparing againstL; refusal retains
the new count and consumes no input. Mode0 ignores count/limit.
N>8 takes fast route (cmp/jbe2cd7aed/2cd7af1 and582127d/5821281).
Direct0..250 consumes1 and returns rawtag18,value=marker. FB/FC/FD select
u16/u32/u64LE atP+1 and consume3/5/9 via the three bound dispatch tables.
No minimum-value restriction: nonminimal encodings accepted in this scope.
FE/FF fast errors return rawtag3,field1=2,field2=4/12, consume0.
N<=8 calls GOT64e6c38 ->58225c0 withDL0. Empty returnsrawtag0,additional1,
consume0. Any present marker is consumed BEFORE classification (58225d9/25dc).
FB/FC/FD shortfall returnsrawtag0,additional(totalwidth-N), consuming ONLY1.
Successful short-path values consume their total width. SlowFE/FF errors
return rawtag3,field1=3,field2=4/12,consume1. Rawconstructor5822700 writes
only tag/field1/field2. All returns still retain the upfront count charge.

Aggregate copies2cd7d90 and5821540 make four direct scalar calls. Mode1 first
checked-add32; overflow retainsC; limit refusal retainsC+32; neither reads input.
After allowed precharge, unclaim8 before each scalar restores fullC+32 after
that call, including errors after partial input. Mode0 leavesC unchanged.
Success returns outertag0 and four values. First scalar error returns outertag1
and its active fields; earlier successes are not an error result payload.
The raw19 diagnostic and unclaim-underflow paths cannot be reached by these
closed scalar outcomes with canonical modes/disjoint memory. Their external
panic implementation/semantics remain unclaimed. Unknown service callers,
original ownership/types and full-codec semantics are excluded. No gate change.

Frozen corpus: generator is a mathematical projection of the above native
loads/branches, not a target interpreter and not a dynamic target oracle.
Exhaustive first-byte/short-length cases plus counter/payload/aggregate boundaries
exercise stated relations; matching them is static-contract validation only.
No original binary execution, no source/binary identity or whole-node proof.
