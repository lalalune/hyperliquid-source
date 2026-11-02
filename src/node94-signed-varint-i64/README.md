# Node94 signed64 slice decoder projection

`read_i64(&mut &[u8], raw_dl: u8)` returns the signed value or the defined
logical error fields and advances the slice exactly as the complete357-byte
leaf at ELF VA`0x4b6fa60..0x4b6fbc5`. Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The full native proof, actual helper/table/GOT closure and independent wire
authority preceded this source (RE-005-signed-varint-i64-94 packet).

Raw DL0 selects little-endian payloads; all nonzero bytes select big endian.
The scalar inverse-zigzag relation covers every u64 payload, including both
i64 endpoints. Nonminimal FB/FC/FD representations remain accepted.

Length>8 uses the native fast relation. Invalid FE/FF consume zero bytes and
report raw codes8:10/8:12. Length<=8 delegates to the existing accepted u64
Reader: nonempty failures consume their marker, and invalid FE/FF become
9:10/9:12. Empty input consumes nothing and needs one additional byte. Both
type-error bytes map c<6 to c+6; other codes and shortfall counts survive.

`ReaderError` and `PayloadOrder` are the existing project's research types.
Their Rust memory layout is not an original ABI claim. Only the active value,
shortfall or two code bytes are projected; native inactive/padding bytes remain
unspecified. No outer limit/counter, arbitrary pointer alias, caller unit or
whole-codec equivalence is inferred.

The real read-only source dependency is the existing MIT component
`src/bincode-varint/src/lib.rs`, whose Reader owns the closed330-byte unsigned
Reader/error-builder dependency. Existing source and manifests are unchanged.
That dependency uses std (including unrelated encoders and error formatting),
so the composed research build requires std despite this new crate's no_std attribute.
The task runner builds that library and this library directly with authenticated
research rustc1.94.1, edition2024, overflow checks, one codegen unit and O0/O3.
The real manifest and offline-generated lock contain exactly these two local
packages. Cargo1.89.0 was hash-verified and used with explicit rustc/rustdoc1.94.1
and a fresh empty owned Cargo home for lock generation and locked offline
metadata validation. No registry, invented workspace or captured object is used.

The production client accepts exactly one stimulus path. Four raw fields
`id|rawDL|lowercasehex|calls` supply bounded calls1..4, without expected output
or semantic roles. It emits sorted compact JSONL with active values and full
cursor/tail observations. Null means outside the logical projection. This is
input data flow, not an operating-system sandbox.

One ordinary unit method uses twenty unchanged first-call vectors extracted
after source authoring from the independently frozen pre-Rust authority. Production
comparison uses all27,671 independently frozen stimuli/89,218 observations.
Actual O0/O3 clients each matched all89,218 expected observations. One20-vector
ordinary method passed per profile; all three normal wrong variants produced
logical mismatches and genuine failing assertions. The locked offline Cargo
build passed using the real dependency. The signed O3 rlib alone rebuilt raw
equal with its unchanged qualified dependency; this is not target-byte identity.
Only independently authored Rust executes; no captured target or instruction
interpreter is involved. New code/docs use MIT; captured evidence retains its
original rights. Original compiler/source/ABI and target-byte identity remain open.
