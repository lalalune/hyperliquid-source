# Independent source relation

This is a normal-return value/state proof for the three newly qualified native
bodies (982 bytes / 289 rows), not original source or ABI identification.
The immutable `NORMAL-DOMAIN.md` and independent pre-source proofs define the
premises and inactive-field exclusions.

`validate_bytes` advances a sequence boundary monotonically. At each boundary
an ASCII byte advances one; C2..DF, E0..EF and F0..F4 require respectively two,
three and four bytes. The second-byte restrictions for E0, ED, F0 and F4 are
exactly the lower/upper Unicode scalar bounds. Every remaining byte must be
80..BF. A missing byte yields None; a present invalid continuation at offset
1/2/3 yields that offset, and an invalid lead yields Some(1). Thus induction on
the first unvalidated boundary gives the first failing sequence and logical
Option length. The native ASCII alignment/bulk optimization changes only how
an ASCII run is skipped, as proved separately for all eight residues. Source
validation uses byte predicates directly, with no standard UTF-8 delegation.

The private header bridge composes the genuine unchanged accepted Reader/fast
implementation. Length greater than eight selects the fast decoder; shorter
inputs select the consuming Reader. The bridge maps only active errors and
the proven fast expected-code difference. It adds the observed fixed charge
when the raw mode's low DWORD equals one, before invoking either decoder.
This is credited dependency composition, not another generic wrapper recovery.

Each nonoverflow charge calls `CounterStores::assign`, which performs the
production counter assignment and appends its value. The limit comparison
follows that call. There can be at most two assignments: header and payload.
Payload charging uses the complete nonzero mode QWORD. Because an equal-value
assignment is recorded, length zero retains the native store observation.

After the length prefix, insufficient payload is checked before allocation or
conversion to usize. A valid Rust slice has length at most isize::MAX, so an
available length is representable and cannot enter either native negative-
length/capacity niche arm. In particular, huge unsigned lengths with mode zero
return payload shortage; no allocation is reached. A shortage preserves the
available suffix, while the earlier prefix and charges remain committed.

For available positive length, `.to_vec()` genuinely allocates and copies the
selected immutable payload. Only after that copy does the cursor advance.
Zero length uses an empty Vec without reading memory. Validation success
constructs the private owned-byte type; validation failure drops its new Vec
before returning the active error and release-request length. Ordinary native
allocation/copy/release functionality remains an explicit premise; its TLS,
unwind, addresses, allocator failures and transitive bodies are not implemented
as fake dependencies and receive no closure claim.

The input-only client forwards input-derived state to the production API. It
serializes returned active fields and actual counter assignments; expected
records never enter the client. Validator input storage is actually positioned
at the requested pointer residue using a safe owned allocation and verified
before the call. Logical None carries no inactive byte, and six native padding
bytes are excluded. Source/test fixtures were selected before source from the
immutable independent authority. Additional tests exercise repeated calls and
owned buffer lifetime, not captured pointer identity.

The qualifier requires complete canonical raw JSONL equality at both
optimization levels, real assertion failures for eight compiled semantic
counterfactuals, copied-ELF rejection controls below the full target hash gate,
and stable physical inputs/provider/host tools. The actual run on source
checkpoint `b8cc0ec0547753707eaa55572513627526452d5c` passed these checks;
`RUST-RESULT.json`, complete retained streams and `ACTUAL-REVIEW.json` bind the
observed outputs and the independent audit. This proof's scalar/source relation
does not depend on the finite corpus being exhaustive over all input lengths.
No captured program or instruction evaluator is executed. Full component and
original compiler/machine-byte gates remain false.
