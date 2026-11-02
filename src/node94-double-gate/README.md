# Node94 COMISD gate with complete numeric RAX

This safe `no_std` library reconstructs the full 27-byte leaf
`[0x5028a40,0x5028a5b)` for node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It adds the full pointer-derived RAX and ordinary comparison domain to the
predecessor's static low-byte gate evidence.

`compare(image, image_base, object, mode)` reads a little-endian pointer P
at the wrapped numeric address `object+0xf38`, then reads its binary64 payload.
On an admitted comparison it returns `(P & !0xff) | gate`, where gate is one
exactly for an ordered value at least positive 1.0. SETAE replaces AL only;
returning a full-width boolean would lose the upper 56 bits of P. The library
uses integer classification and comparison, with no host floating operations.

`CompareMode` describes invalid-operation masking, denormal-operand masking
and denormals-are-zero (DAZ). These are separate booleans, not raw MXCSR.
COMISD signals invalid for both quiet and signaling NaN. Unmasked invalid,
or unmasked denormal with DAZ disabled, produces a new safe refusal. DAZ
suppresses denormal admission failure independently of its mask. These
refusals do not reconstruct original exceptions or handler behavior.

The slice represents one nonwrapping numeric address interval. The field
and payload may overlap; only reached complete eight-byte spans are required.
Numeric addresses never become Rust pointers. Image-range, field and payload
refusals precede floating-class admission in that order. The statically bound,
unchanged 1.0 literal is an original-correspondence premise, not a third
optional span in this API. No data is written on any path.

Original correspondence requires stable ordinary memory, readable unchanged
constant data, supported comparison controls and normal instruction/return
control. Faults, MMIO, races, handlers, XMM/flags/MXCSR status, native ABI and
original compiled-byte identity are outside the projection. Synthetic numeric
wrap cases do not assert that those addresses are mapped by a real process.

The [evidence packet](../../research/work-items/RE-004-double-gate-rust-94/README.md)
and [proof](../../research/work-items/RE-004-double-gate-rust-94/PROOF.md)
contain the complete bit-domain derivation, primary Intel references, original
bytes/FDE/data/relocation bindings, pre-Rust oracle and native qualification.
The input-only driver accepts a 147-byte descriptor/image record and emits a
nine-byte tagged result; it receives no expected outputs or target instructions.
