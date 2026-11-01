# Node94 paired fixed-prefix readers

`read_20` and `read_32` reconstruct the complete logical relation of node94
`0x466c140..0x466c1a6` and `0x466c1b0..0x466c223`: 217 bytes/69 instructions.
Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The portable functions take a mutable remaining slice, raw u32 mode, u64 limit
and charged count, and an initialized21/33-byte output array. These are own
research interfaces; addresses, original nominal types and ABI remain unknown.

Only mode exactly1 charges. Overflow preserves the old charged count. Otherwise
the increment survives a limit rejection or shortage. Failures preserve the
slice; success copies exactly20 or32 prefix bytes and advances that width.
Result write sets differ: twenty-byte success has rawtag18, whereas32-byte
success has leading0 and errors leading1 plus a code at+8. All other result
bytes preserve the supplied initialized contents. No uninitialized real-caller
padding, arbitrary aliases, fault/unwind or intermediate store order is modeled.

The independent native/domain proof and50,391 raw stimuli/122,634 canonical
observations were frozen before this source. Twenty selected full multi-call
stimuli/50 observations were also sealed before Rust authoring and form one
ordinary unit method. Both widths remain one family contribution. Existing
kind5's charged-varint pattern and old stream-message static context are
credited; neither provided this generic fixed-prefix/result relation.

The production observer accepts exactly one eight-field stimulus path:
`id|width|mode|limit16hex|charged16hex|wirehex|initializedoutputhex|calls`.
Widths are20/32, mode u32, calls1..4. It emits all12 sorted compact JSONL keys,
including the full initialized output, exact u64 charged count and complete
tail. Expectations and semantic roles never enter its arguments. This input
data flow is not an operating-system sandbox.

The library is safe no_std and dependency-free. The real component manifest
and genuine offline Cargo lock describe exactly one local package; the std
observer/test harness are research validation tools. Selected Cargo1.89.0
generated the lock and passed locked offline metadata with explicit authenticated
rustc/rustdoc1.94.1 and an empty owned Cargo home. The first actual qualification
passed: O0/O3 each matched all122,634 observations, one20-stimulus/50-observation
unit method per profile passed, twelve native/static methods passed and the
genuine locked offline Cargo build passed. Three normally returning wrong
variants produced logical mismatches and actual failing unit assertions.
The optimized rlib alone rebuilt raw equal; this is not target-byte identity.

See `research/work-items/RE-005-fixed-byte-readers-94` for every native row,
full FDE/CIE/caller/RELA closure, original mathematical seals, source proof and
actual validation scope. New code/docs are MIT; captured evidence retains its
original rights. No selected compiled-byte comparison, original compiler/ABI,
full caller/codec/node equivalence or component gate is claimed.
