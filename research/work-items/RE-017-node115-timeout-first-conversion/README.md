# RE-017: Select a decoded #115 Timeout Block for first conversion

The selected replay worker compares identity using the incoming parent's appropriate quorum. For a Timeout Block, that is the optional quorum when present and the embedded quorum otherwise. The following successor comes from the separate leading timeout value plus one. This fixture joins both decoded operands to the existing conversion cursor, then verifies the actual selected wire header against the archive and adjacent Context references. [Recorded worker identity](../RE-017-node115-replay-record-identity/README.md) · [Decoded parent layout](https://github.com/lalalune/hyperliquid-source/pull/7424) · [First conversion fixture](https://github.com/lalalune/hyperliquid-source/pull/7645)

The synthetic checkpoint has height 42 and restored round 40. A Timeout Block uses optional quorum identity 40, embedded quorum identity 37, and timeout value 49. Its prepared owner is empty. The selected identity matches, and the timeout successor 50 reaches the empty-input threshold immediately. The archive at H+1=43 retains parent round 40 and admitted round 50, and all selected Context leaves match. A second fixture uses an absent optional quorum and embedded identity 40, with the same result. An absent optional quorum with embedded identity 37 fails the first identity check. Keeping identity 40 but reducing the timeout value to 48 yields successor 49 and no conversion.

This fixture is a structural offline check with synthetic consensus records and reference trees. Actual replay admission, actions, and complete production H/H+1 parity need independent evidence. The native verifier reads the Linux x86-64 #115 ELF with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` as data and runs only reconstructed Python and Rust.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with msgpack 1.1.2, Rust 1.95, and the exact pinned Git snapshots in the verifier.

```sh
python3 -B -u "$packet/verify.py"
```

The focused patch applies to the exact cursor fixture in a temporary directory. See the [raw offline run](offline-log.txt).
