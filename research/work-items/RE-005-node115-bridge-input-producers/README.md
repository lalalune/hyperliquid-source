# Node #115 bridge `requestWithdrawal` producer path

## Question and scope

Issue [#3917](https://github.com/lalalune/hyperliquid-source/issues/3917)
leaves bridge request formats and canonical hashes open. Existing #115 packets
follow the outer 52-byte bridge-builder input and its final 32-byte result, but
leave the origin of the second 32-byte field outside scope. This packet traces
one concrete producer: the input record whose first byte is 5 and whose fixed
label is `requestWithdrawal`.

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source snapshot/base: repository `main` at
`0781ce04826eeefd89fe336cb8ea073be0c1de30`; no upstream source bytes are used.
Component/task: bridge, RE-005 / RE-001.

This is a static, address-bounded path. It does not name private source types,
assign public field meanings, prove runtime reachability, or claim a complete
bridge request/hash/signing implementation.

## Observed path

Two caller sites reach the outer helper through relocation slot `0x64eaae8`,
resolved by `.rela.dyn` as `R_X86_64_RELATIVE` to `0x4526e40`. The first
prepares an input record with byte tag 4; the second prepares byte tag 5. They
are different source variants and must not be collapsed into one general
schema. The constructor slot `0x64eab68` resolves to `0x4526230`.

For the tag-5 caller path:

1. `0x4526230` reads the record's first byte and dispatches through the signed
   relative table at `0x7d3708`. Entry 5 lands at `0x45267ed`.
2. That arm reads qwords at record offsets `+0x30` and `+0x38`. It constructs
   the 17-byte label from the 16-byte `.rodata` prefix `requestWithdrawa` at
   `0x7d3bbc` and the literal byte `0x6c` (`l`) written at label offset 16.
3. The same arm copies four source spans: 16 bytes from `+0x1`, 4 bytes from
   `+0x11`, 16 bytes from `+0x15`, and 4 bytes from `+0x25`. These are raw
   source offsets, not recovered public fields. It passes the constructed
   record through `0x44e96a0`.
4. The returned pointer and length are passed to absorb slot `0x64e0148`, which
   relocates to `0x5cda910`. The path then requests 32 output bytes through
   slot `0x64e0150`, relocated to `0x5cdad40`. The common constructor copy
   branches to `0x4526d00`, which copies 32 bytes into its output buffer.
5. The outer helper copies 20 bytes from its separate first-field buffer to
   offsets `+0x50..+0x63`, then copies the constructor's 32-byte result to
   `+0x64..+0x83`. It passes the contiguous 52-byte view at `+0x50` to
   `0x4302cd0`.

This establishes that the tag-5 `requestWithdrawal` record contributes the
second 32-byte field of this selected 52-byte input. The first 20-byte field
has a separate producer and remains outside this packet. The tag-4 arm instead
delegates to `0x3676390`; its output semantics are not generalized from the
tag-5 result.

Open PR [#4333](https://github.com/lalalune/hyperliquid-source/pull/4333)
describes the downstream 52-byte-to-64-byte preimage and final inner digest.
This packet covers the upstream tag-5 producer for its second 32-byte input
field. It does not establish that the field is an EIP-712 digest, a canonical
request hash, or an authorization value.

## Evidence and reproduction

`evidence.json` records instruction bytes and their complete containing FDE
extents, four relative relocations, the switch-table entries, the fixed string
bytes, and the bounded observations above. FDE ranges are unwind extents, not
claims of validated function boundaries. No captured code was executed or
emulated.

From repository root:

```sh
python3 research/work-items/RE-005-node115-bridge-input-producers/verify.py
python3 tools/verify_packets.py
git diff --check
```

The focused verifier checks the full artifact digest, 16 selected instruction
anchors, their FDE extents, four `R_X86_64_RELATIVE` entries, switch-table
targets, the literal prefix, and a one-byte instruction-corruption control.
`make doctor` reports `analysis_ready=true` with GNU binutils 2.47.20260726.
`make verify` was attempted in the sparse checkout and stopped because the
unpinned-working-tree source submodule `upstream/block-importer` was not
materialized; it is unrelated to this packet. Full test discovery and
catalogue checks were not run because this evidence-only change adds no
implementation, tooling or catalogue entries.

## Limits and next step

Still unknown: the public meaning of the four copied spans; the precise
encoding produced by `0x44e96a0`; the tag-4 output; the separate 20-byte field;
the finalized sponge's algorithmic identity from this packet alone; runtime
occurrence; caller-level authorization, nonce, persistence and rollback. The
next bounded bridge question is to map the tag-5 record's caller-side source
fields and compare them with the distinct tag-4 path, keeping any inferred
names separate from the observed offsets.
