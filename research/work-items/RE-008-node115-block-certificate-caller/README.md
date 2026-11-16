# Variant-0 block bytes and the nested-certificate caller (node/115)

This packet reconstructs the successful logical serialization used by the
actual caller at `0x4fae100`, and composes that caller with the existing nested
certificate implementation. It advances the RE-008 validation integration path:
the caller can now compute its block digest rather than accept an unrelated
precomputed digest. It does not establish a complete consensus verifier.

Target: `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All native evidence is static. No captured code was executed or emulated.

## Prior work and remaining scope

- #6459 and `RE-008-node115-nested-certificate-decision` own `0x595fd20`,
  the variant-1 vote frame, stake-provider and signature-primitive contracts,
  and reusable Keccak/SigMap code. This contribution reuses them. Variant 0
  has a different body; it cannot use variant-1 bytes as its hash input.
- `RE-008-signed-message-admission-115` owns `0x57e8970`. Its full front-end
  semantics remain a supplied closure, invoked with the same logical block,
  nested certificate, and context. Returning success is a substantive premise.
- #2916 documents decoder-side Block structure. This packet adds the actual
  writer graph and caller composition, not a new claim to that decoding work.
- Existing compact-u64 and Keccak implementations are reused without changing
  their pinned source. Curve recovery, stake lookup, TC admission, and native
  map allocation/iteration reconstruction are outside this contribution.

Fresh all-state searches covered the caller and writer addresses, and the
relevant prior packets were compared before publication. Shared helper bytes
are supporting evidence, not claims that those helpers are newly discovered.

## Serialized bytes

`0x5823db0` uses tables `0x935c44` and `0x935c58`; index zero selects the
size helper `0x5967290`, then writes byte `00` and calls `0x5967060`.
For block base B, that writer emits, in order:

| Input | Encoding |
| --- | --- |
| B+0x11c | 20 raw bytes (`0x58221e0`) |
| count B+0x10, pointer B+8 | compact-u64 count, then 32 raw bytes per element |
| B+0x110 | signed epoch seconds zigzag-u64, then compact-u32 nanoseconds |
| B+0x18 == 0x8000000000000001 | compact discriminator 0, certificate B+0x20 |
| otherwise | compact discriminator 1, u64 B+0xa0, certificate B+0x18, TC map B+0x80, optional certificate B+0xa8 |

Certificate writer `0x5966a30` emits five compact-u64 words at offsets
0x20,0x28,0x30,0x38,0x40, then the raw32 hash at0x48, then the signature map.
The map emits count, and each raw20 key followed by its signature. TC map
`0x4de66a0` instead emits count, raw20 key, compact-u64 value, signature.
Both native tree and ring branches are retained in the transcript. The source
uses the existing SigMap iteration API; TC rows must already be in native
iteration order. It does not silently sort TC rows or remove duplicates.

`0x59681d0` writes a signature as **eight compact-u64 little-endian limbs**,
followed by a raw recovery byte. It does not copy 65 raw bytes and does not
write array lengths. Optional certificate `0x4e05700` writes byte0 for the
sentinel, otherwise byte1 followed by the certificate.

Timestamp writer `0x4ecaba0` first projects the packed native calendar to
epoch seconds, then zigzags it and encodes nanoseconds. The source deliberately
accepts the correctly projected `seconds:i64,nanos:u32`; it does not claim to
decode or validate the native packed calendar. Boundary fixtures at i64
extremes exercise the logical API, not representable captured calendar values.

On normal serialization success (tag8), `0x57e8d40` concatenates the 29 bytes
`Hyperliquid Consensus Payload` with the complete variant0 message. The
Keccak state has rate136 and delimiter1, with update/final relocation bindings
to `0x5cda910`/`0x5cdad40`, producing32 bytes. This is Keccak-256, not SHA3-256.
Source allocation succeeds or fails according to the host; native allocation
and size-pass failures are outside the logical successful-output contract.

## Actual caller order

At `0x4fae100`, B is the same RSI input throughout. The checks are:

1. Call `0x57e8970(B, context)`; propagate non-0x2e output.
2. Call `0x595fd20(B+0x178, same context)`; propagate non-0x2e output.
3. Compare external expected hash with the selected parent certificate hash.
   Simple selects B+0x20. Composite selects B+0xa8 when present, otherwise
   B+0x18. Mismatch returns raw0x1d.
4. Compute variant0 digest of B and compare to B+0x1c0/0x1d0, the hash of the
   nested certificate at B+0x178. Mismatch returns raw0x1e.
5. Select Simple's B+0x50 or Composite's B+0xa0, saturating-add1 to it and
   to the independent caller round, then compare. Mismatch returns raw0x1f;
   success returns0x2e. MAX and MAX-1 are therefore equivalent at this gate.

The typed source preserves nested `Diverges`, and keeps front-end errors
opaque. It models normal returned decisions, not the native error ABI,
logging side effects, unwinding, or every outer caller. A successful local
fixture with supplied primitives does not establish a real signature or
authorize any live block.

## Reproduction and validation

`verify.py --target <captured-file>` checks the target, 22 full FDEs /2402
instructions,187 selected witnesses, two Keccak relocations, one memcpy
import, three dispatch tables, two discriminator constants, and15 negative
controls. These checks bind the written interpretation to exact bytes; they
are not execution tests or automatic semantic proof.

`fixture_oracle.py` is an independently written Python encoder using
PyCryptodome4.5.0 for Keccak. It checks the empty and `abc` known vectors,
18 frozen complete byte/hash fixtures, and36 wrong-domain/variant preimages.
`--write` regenerates `fixtures.json` and the dependency-free Rust integration
test; format the generated Rust with `cargo fmt` afterward. Fixtures include
Simple, Composite Some/None, multiple hashes and signature rows, TC iteration
order, compact integer boundaries, signed seconds, nanoseconds, signature
limbs and raw recovery bytes. They are synthetic logical inputs, not native
observations. The Rust caller tests separately check short-circuit order,
parent versus nested digest identity, saturating rounds, and no-return output.

Run the crate's tests with Rust1.95 in debug and release, then fmt and strict
Clippy. Repository reproduction and catalogue checks are also required.
This packet closes the selected writer/caller composition only; the front
check, raw calendar projection, curve primitives, concrete stake provenance,
and downstream acceptance remain explicit dependencies.
