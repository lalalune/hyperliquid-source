# Pre-source native freeze and reuse

Base8fd8db680ec4bfef40996e5616bce3d5156d0b86 has no active115 group-reader
Rust component. The IPv4-prefix Rust algorithm already exists in the project's
own MIT PR2334(source eb0b4600); that dependency is reused with attribution,
not represented as new blind recovery. No unlicensed inferred code is used.
New group-reader Rust is written only after native results, actual corruptions
and source chronology are committed. Native expectations never use that Rust.

The entire477-byte group-reader FDE is interpreted with real CALL/RET into
the original IPv4 leaf and numeric helper. The latter's scope is ONLY the
actual caller-supplied bounded configuration(bounded tag1/max4/radix16/leadingzeros
allowed, with at least one digit required by the result path), not all other callers or generic modes. Unknown paths/instructions
fail rather than substituting helper answers. A packet-local ROL16 addition
is the minimum fix for an observed instruction-model blocker; no maintained
shared decoder or separate tooling PR is changed. The source loader's raw
register/stack memory masks remain unknown until original instructions set them.

The complete341-byte compression wrapper is static context only. It calls this
reader twice and separately uses imported memcpy. No memcpy/import substitute
is part of this oracle, and :: expansion, full IPv6 parsing, imports, panic
helpers and original API/ABI are NOT implemented or credited. This contribution
is one complete bounded group reader plus its helper/caller contract, not a
quota split of whole-IPv6 reconstruction. All full-component gates remain false.
