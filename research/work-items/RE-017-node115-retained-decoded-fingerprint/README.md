# RE-017: Derive the retained predecessor from a decoded #115 Block

The [retained batch trace](https://github.com/lalalune/hyperliquid-source/pull/7306) shows that the previous accepted owner supplies the next row's expected identity and predecessor bytes. The [incoming projection](https://github.com/lalalune/hyperliquid-source/pull/7424) extracts those two values from the incoming quorum fields. The [batch fixture](https://github.com/lalalune/hyperliquid-source/pull/7434) accepts the expected preceding fingerprint as explicit input. This packet shows how both operands can be obtained from two structurally decoded, adjacent synthetic replay Blocks.

The call at `0x4face6f` targets `0x57e8d40`. The same helper underlies the existing [RE-008 variant-zero codec](../RE-008-node115-block-certificate-caller/README.md). Its selected path writes a 29-byte `Hyperliquid Consensus Payload` domain, serializes the Block header with variant zero, and produces a 32-byte Keccak result. The probe uses precisely that codec for the expected fingerprint. It projects the previous decoded address, ordered header digests, clock and direct quorum fields. It restores Unix seconds from the packed signed year and ordinal and checks that the existing admission conversion reconstructs the same clock tuple. The incoming identity and digest come from the existing decoded parent selector.

The bounded adapter accepts a previous direct quorum with an empty vote list. The synthetic examples exercise an ordinary clock before the Unix epoch and a nonempty ordered header-digest vector. The previous identity projection yields 41 from the previous quorum round 40. The incoming quorum carries 41 and the independently calculated preceding fingerprint. The control pairs vary one operand at a time and report a link mismatch. The fixtures contain structural placeholder fields and establish neither acceptance, consensus verification, nor ABCI state-root agreement.

The offline verifier rechecks the retained comparison spans, both helper call destinations, the variant tag, the RIP-relative domain bytes, and the output width using the pinned Linux x86-64 node #115 ELF. Capture SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier then builds the exact existing Rust codec and decoder snapshots and cross-checks canonical serialization and Keccak against an independently written Python fixture generator using PyCryptodome. It reads the target as data and executes only reconstructed code offline.

## Reproduce

From the repository root, use Rust 1.95 and an environment with PyCryptodome 3.23.0, and ensure that the exact commits listed in the verifier are available in the local Git object database.

```sh
python3 -B -u "$packet/verify.py"
```

Set `packet` to this directory. The verifier checks all fixture payloads, runs the successful and two mismatching pairs, and prints exact input hashes and both comparison operands. See the [raw offline run](offline-log.txt).
