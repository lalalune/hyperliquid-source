# Node #115 nested certificate decision

Reconstruction of the node #115 flow that decides a nested certificate: the decision
`0x595fd20..0x596000d`, the verifier `0x595f880`, the equality helper `0x4e08870` with its callee
`0x4e550e0`, the signer collector `0x4e00160`, the per-signature check `0x57e8bd0`, the quorum
`0x595bc40` with the stake test `0x4d3e1a0`, the stake-set provider `0x595e5c0`, and, new in round 4,
the digest builder `0x57e8d40` (message encoding and Keccak-256) and the recovery wrapper `0x1536a90`.
Work item RE-008; instruction-level evidence, the hand-followable relation tables and the frozen
corpora are in the
[static evidence packet](../../research/work-items/RE-008-node115-nested-certificate-decision/README.md).
No progress gate is requested.

## What it does

`decide_nested(&Certificate, &Context, &provider, &primitives) -> Output<Verdict>` runs the decision
and, on the arms that need them, the equality helper and the verifier. `history::StakeHistory` is the
provider `0x595e5c0` (it implements `StakeSetProvider`; the trait stays a seam for tests):

```text
decision -> pair/ordering tests -> equality(sigs, empty)            tags 0x06 / 0x2e
                                -> verify -> provider(round f40)     tag 0x28
                                          -> collect signers         tag 0x2c
                                          -> quorum                  tag 0x07
                                          -> signature check each    tag 0x02, else 0x2e
signature check (per entry) = stake-map membership
   -> digest   = keccak256("Hyperliquid Consensus Payload" || 0x01 || signer || varint(A..E) || hash)   digest.rs, keccak.rs
   -> address  = keccak256(curve_recover(reverse(r), reverse(s), id(v), digest))[12..]                  recover.rs
   -> equal to the signer
```

`verify` alone is `0x595f880`; `Output::tag()` and `Rejection::tag()` give the native tag bytes.
The certificate's signature collection is a tree or a ring (`SigMap`); `SigMap::from_normalized`
builds it from `node115-certificate-long-sort` output. Ring stake maps are summed by
`node115-stake-predicate`. The no-return path is `Output::Diverges`; the crate does not abort.
`primitives::NodePrimitives<C>` is the real digest builder and recovery wrapper around a curve routine `C`.

## What stays outside

* **The curve routine** under the recovery wrapper: three functions of a secp256k1 library compiled into
  the node (`0x632b660`, `0x632b7b0`, `0x632b480` and everything they call). They are named from their
  argument-check texts and group constants (packet rows SP1, SS1, SR1), not reconstructed. They are the trait
  `recover::Secp256k1`; the tests supply stand-ins that return a key the case names or fail. **No real
  signature is verified by this crate**, and a pass of the tests says nothing about libsecp256k1's behaviour.
* Message variants of the serializer `0x5823db0` other than 1, the size pass `0x5966cd0`, the squeezing
  modes of the hasher. `NodePrimitives::digest` panics for a variant other than 1.
* The value-level model of the containers: history search, tree iterator, drops, allocation, concurrency of
  the provider's counter, the native ABI. Malformed native structures are outside the model, and the three
  ring constructors check different things: `StakeMap::ring` and `Rounds::ring` refuse a bad shape (`len`
  above capacity, `head` not below capacity) and live rows that are not in key (round) order, which the
  native binary searches need; `SigMap::ring` checks only the shape, so a signature ring may hold its keys
  in any order and is visited in ring order from the head (no order requirement is read from the bytes). The
  enums `SigMap`, `StakeMap` and `Rounds` are public, so building a `Ring` variant directly skips the
  constructor's checks and can panic or revisit rows; that is outside the model too. Output record bytes the
  native code leaves uninitialised are not represented.

## Prior work reused

`digest.rs::put_varint` is one call to `node115_varint_buffer_writer::write_u64` (`RE-005-varint-buffer-writer-115`,
the base tree's crate for `0x5822910`, path dependency); the varint rule is that packet's finding, not this one's.
It reports an allocation refusal as an error value where the node's path does not return, so `put_varint` panics on
it. The parent serializer's jump tables and the 20 byte copy `0x58221e0` were first read by
`RE-005-fixed20-record-encoder-115` (the arm with tag byte 2); this crate has the arm with tag byte 1. Also reused:
`node115-stake-predicate`, `node115-certificate-long-sort`; `node115-sponge-permutation` has no `Cargo.toml`, so only
the tests compare against it.

## Validation

None of this is run by the repository's `make test` (Python `unittest` discovery) or `make verify`; run the commands
by hand. The packet's own checks (`verify_target.py`, `mutate.py`, corpus regeneration) are listed in its README.

```sh
OUT=<a new empty directory outside the checkout>
cargo test --offline --locked --target-dir $OUT/target --manifest-path src/node115-nested-certificate-decision/Cargo.toml
cargo test --offline --locked --release --target-dir $OUT/target-release --manifest-path src/node115-nested-certificate-decision/Cargo.toml
```

Twenty-seven tests per profile. Eighteen from rounds 1 to 3: the 621-case decision corpus and its
drop-once check; seven corpora of the flow functions (equality 225, collector 54, signature check 144,
quorum 934, provider 522, verifier and decision end to end 471, certificates of more than 64 signatures and
empty ones 43, each `mismatches=0`); five tests of which signature each entry receives (`tests/sigslot.rs`);
a hand-derived end-to-end test through the provider; the ring-constructor refusals; two long-sort reuse
tests. Nine from round 4 (`tests/digest.rs`): the hasher on 347 cases (public SHA3-256 and Keccak-256
vectors, SHA3-256 from the standard library on 171 lengths around the rate, Keccak-256 on the same lengths,
each also fed in pieces), the permutation against `node115-sponge-permutation` on 300 states, the digest
builder on 279 frames (every varint class at every word position, every signer and hash byte), one preimage
written by hand from the disassembly, the recovery wrapper on 370 signatures (every `v`, byte order, curve
failure), whole certificates through `verify` with the real digest and a stand-in curve routine (13
signatures in 4 certificates; every word and hash byte is bound by the digest), a signer check, and the
refusal of other message variants. All 104 compiled wrong implementations fail (packet `mutations.tsv`).
Built and tested with cargo 1.99.1; `rust-toolchain.toml` pins 1.95.0 like the sibling `node115-*` crates
but was not honoured by the installation used. `cargo fmt` and `cargo clippy` were not run. The expected
values come from the packet generators, written from the disassembly before this code (the digest side was
frozen first, `ORACLE_FROZEN.txt` FREEZE 4); there was no native differential run.
