# RE-004: multi-step admission decision of PxPriv (node #94)

- Component ID: RE-004 (quantities/rounding; Px / PxPriv newtype admission)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/qtys/impl_px.rs` and `references/can1357-hl/l1/qtys/mod.rs`
  (diagnostic labels and visitor search leads only; zero code copied)
- Claim status:
  - Observation for byte-level disassembly facts, exact instruction addresses, rodata diagnostic pieces, FDE boundaries, direct calls (`call rel32`), and caller guard byte sequences.
  - Inference for the simulated predicate models evaluated over sample inputs, caller serialization roles (JSON, MessagePack, Bincode), and visitor monomorphizations.
  - Unresolved items listed at the end.
- Scope included and excluded:
  - Included: the three rodata diagnostic pieces:
    1. `invalid value {} for PxPriv when visiting u64`
    2. `invalid value {} for PxPriv when visiting i64`
    3. `invalid value {} for PxPriv converting to intermediate u64 when visiting i64`
    every RIP-relative LEA that loads them in `.text`; the FDE-bounded constructor
    functions holding those LEAs; every direct `call rel32` to those constructors;
    the multi-step admission decision guards (bounds checks, intermediate sign/zero
    conversions) routing each caller; and error branch entries.
  - Excluded: zero execution of captured binary (static observation and offline
    disassembly only); no runtime or binary equivalence claim; NtlPriv, BigNtlPriv,
    SzPriv, SziPriv, NtliPriv (covered in `RE-004-qty-newtype-sign-guards-94`);
    WeiPriv (covered in `RE-004-weipriv-sign-guard-94`); indirect calls/jumps into
    constructors; downstream arithmetic (`checked_add`, `checked_sub`, `saturating_add`,
    `saturating_sub`, `mul_size_raw`, rounding, tick quantization); decimal wire-format
    string parsing (`parse_wire`); and node #115 / visor targets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12+
(standard library only), GNU objdump 2.42+ / llvm-objdump for optional human cross-check.
The binary is only read offline; nothing is executed.

```sh
python3 tools/artifacts.py verify
python3 tools/pxpriv_admission.py --out research/work-items/RE-004-pxpriv-admission-94
python3 -m unittest tests.test_pxpriv_admission -v
sha256sum -c research/work-items/RE-004-pxpriv-admission-94/MANIFEST.sha256
# optional human cross-check: objdump disassemble selected caller and constructor FDEs
# objdump -d -M intel --start-address=0x199fa00 --stop-address=0x199ff99 artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It writes `evidence.json`,
`call-sites.tsv`, and `guard-bytes.txt` alongside `MANIFEST.sha256`.

### Repository verification status & environment limits
- `tools/artifacts.py verify`: All 8 artifact SHA-256 digests verified OK (including `artifacts/node/94/hl-node: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
- `tools/verify_imports.py`: Verified 37 imported files and all pinned source repositories.
- `make verify` / `make test` / `make catalogue-check`: Full repo-level make harness was not run directly in this environment due to missing native POSIX make/gpg toolchains on Windows. All unit tests for this packet (`tests/test_pxpriv_admission.py`) pass 8/8 cleanly.
- Differential/runtime execution: Intentionally excluded. Offline static observation only; no binary execution or runtime equivalence claim.

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset;
`.text` starts at VA `0x1343c80` (offset + 0x1000). Function extents come from
the `.eh_frame_hdr` search table (121,299 entries) plus each FDE's own
`pc_begin`/`pc_range`.

1. Diagnostic pieces. Exactly three primary visitor diagnostic pieces exist in `.rodata`:
   - `0x1e66bc`: `"invalid value \xc0\x1d for PxPriv when visiting u64\0"`
   - `0x1f7a89`: `"invalid value \xc0\x1d for PxPriv when visiting i64\0"`
   - `0x1ff911`: `"invalid value \xc0< for PxPriv converting to intermediate u64 when visiting i64\0"`
   (Auxiliary lead: `0x1ebe69`: `"\nNonZeroU64\xc0\x0b for PxPriv\0"`).
   Each piece starts with length byte `0x0e` (`"invalid value "`), followed by format marker and literal.

2. Loads of the diagnostic pieces.
   12 RIP-relative LEAs in `.text` resolve into the four pieces, exactly three per piece:
   - `u64` (`0x1e66a6`): `0x22e4c86`, `0x3252446`, `0x325248a` (constructors `0x22e4c70..0x22e4cae`, `0x3252430..0x325246e`, `0x3252470..0x32524b5`)
   - `i64` (`0x1f7a73`): `0x22e4c36`, `0x3252306`, `0x325235a` (constructors `0x22e4c20..0x22e4c66`, `0x32522f0..0x3252336`, `0x3252340..0x3252385`)
   - `intermediate_u64` (`0x1ff8fb`): `0x22e4be6`, `0x32523a6`, `0x32523fa` (constructors `0x22e4bd0..0x22e4c16`, `0x3252390..0x32523d6`, `0x32523e0..0x3252425`)
   - `NonZeroU64` (`0x1ebe57`): `0x23943f2`, `0x32853e2`, `0x45ac832` (vtable trait methods `0x23943d0..0x239445d`, `0x32853c0..0x328544d`, `0x45ac810..0x45ac89d`)

3. Callers.
   27 direct `call rel32` sites reach the 9 visitor constructor FDEs across 9 unique caller functions
   (9 calls for u64, 9 for i64, 9 for intermediate_u64; 0 direct calls for NonZeroU64 vtable methods).
   The 9 caller functions comprise:
   - Set 1 (JSON/text format, 1733 bytes each): `0x2812c00..0x28132c5`, `0x2813320..0x28139e5`, `0x2813af0..0x28141b5`
   - Set 2 (MessagePack/binary integer decoder, 896 bytes each): `0x2e625e0..0x2e62960`, `0x2e957e0..0x2e95b60`, `0x2ee1ec0..0x2ee2240`
   - Set 3 (Bincode/compact wire visitor, 1733 bytes each): `0x35938d0..0x3593f95`, `0x3593fa0..0x3594665`, `0x35947f0..0x3594eb5`
   Every single caller function contains all three visitor error constructor call sites.

4. Multi-step admission predicate.
   - For `u64`: guarded by zero-check (`test r,r; je <error>`). Zero is rejected; any non-zero u64 (`value > 0`) is admitted.
   - For `i64`: multi-step admission:
     1. Step 1 (intermediate conversion): `test r,r; js <error>` / `jns <ok>` checks the sign bit.
        Negative values (SF=1) trigger the error constructor for intermediate u64 conversion.
     2. Step 2 (zero check): `test r,r; jne <ok>` checks for zero.
        Zero (ZF=1) triggers the error constructor for visiting i64.
     Combined admission: strictly positive values (`value > 0`, range `1..i64::MAX`).

5. Accepted value preservation.
   On the accepted path, the validated value is stored unchanged to `[rdi+8]` and tag byte `9` (`Ok(NonZeroU64)`)
   is written to `[rdi]` without clamping, scaling, or rounding.

Analysis is complete for the declared scope (full `.text` scan for LEAs and direct calls;
full caller FDEs scanned for guards and branches).

## Implementation and comparison

Packet generated with deterministic tooling `tools/pxpriv_admission.py`. No Rust component or binary equivalence claim yet.
An independent clean-room Rust implementation must:
1. Accept input integer values conforming to the exact multi-step guard logic verified in node #94.
2. Produce authentic diagnostics matching the observed `.rodata` strings on rejection.
3. Be independently authored under MIT license without copying from unlicensed reference trees.
4. No differential execution was run (RE-003 harness unavailable); zero runtime equivalence claim is made.

## Results and limitations

- Metrics (denominators explicit):
  - Diagnostic pieces verified in `.rodata`: 4/4.
  - RIP-relative LEAs in `.text`: 12/12.
  - FDE-bounded constructors: 12/12.
  - Caller functions: 9/9.
  - Direct call sites: 27/27.
  - Predicate sample vectors verified: 190/190.
- Unit tests:
  - `tests/test_pxpriv_admission.py` (8/8 passing): input digest mismatch refusal,
    missing artifact rejection, synthetic direct call decoding, admission models,
    piece layouts, caller extents, negative controls, and byte-for-byte manifest verification.
- Inferences, not proven:
  - High-level visitor/serde roles and struct identities are inferred from search leads;
    binary evidence grounds exact VA coordinates, instruction opcodes, and control flow graphs.
- Unresolved:
  - Monomorphized caller struct ownership; indirect calls to constructors; downstream tick/rounding interactions.
- No progress gate is requested.

Next question: How does Px order-wire scale validation interact with runtime asset metadata
(perp 1e6 vs spot 1e8 decimal envelopes)?
