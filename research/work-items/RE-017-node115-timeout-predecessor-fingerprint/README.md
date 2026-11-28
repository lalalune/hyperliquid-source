# RE-017: Derive a retained fingerprint from a decoded #115 Timeout parent

The retained fingerprint fixture derives the preceding Block's canonical variant-zero digest from a decoded direct-quorum parent. This extension feeds the timeout certificate, its embedded quorum and an independently present optional quorum to the existing canonical serializer. The preceding timeout scalar determines the expected next identity. The embedded and optional quorum rounds remain their own fields in the canonical body. [Direct predecessor fixture](https://github.com/lalalune/hyperliquid-source/pull/7625) · [Selected parent layout](https://github.com/lalalune/hyperliquid-source/pull/7424)

The two synthetic predecessors have timeout value 44 and embedded quorum round 38. One also carries an optional quorum at round 40. Both yield an expected subsequent identity of 45, and the two canonical fingerprints differ. The independent Python encoder and PyCryptodome reproduce the complete serialized bytes and Keccak fingerprints. The subsequent wire fixtures carry the appropriate predecessor digest. Controls using the embedded or optional quorum round as the successor basis fail. A fingerprint that ignores the optional quorum also fails despite the correct next identity. The original direct-quorum fixture continues to pass.

The scoped predecessor adapter handles structurally decoded, ordinary shapes with empty quorum and timeout vote lists. It composes the existing selected #115 evidence and codec. Signature operations, whole consensus admission, production provenance and state roots remain separate. The pinned Linux x86-64 #115 ELF is read as data, with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Rust 1.95, Python with PyCryptodome 3.23.0, and the exact Git source snapshots listed in the verifier.

```sh
python3 -B -u "$packet/verify.py"
```

The patch applies only to the exact predecessor probe in a temporary directory. See the [actual offline run](offline-log.txt).
