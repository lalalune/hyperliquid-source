# Node #94 timeout, heartbeat and acknowledgement preimages

This packet closes consensus selectors **2–4** as one serializer/sizer family
and adds offline value APIs in
[`message_preimages.rs`](../../../src/node94-consensus-admission/src/message_preimages.rs).
It binds node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes, against main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
No captured executable or instruction evaluator was run.

The contribution is a bounded new contract, not a bug claim about the existing
opaque `Qc` or authenticator interfaces. It does not depend on unmerged QC-vote
PR1391 or bincode-wrapper PR1365. The two local dependencies already exist on the
pinned main: MIT `hl-bincode-varint` and MIT `node94-action-signable`.

## Recovered bytes

`V` is the existing minimal little-endian unsigned varint, `O(None)=00`, and
`O(Some(x))=01 || encode(x)`. All three preimages start with the exact 29 bytes
`Hyperliquid Consensus Payload`; the timing label `consensus msg` is separate.

| Selector | Bytes after the common prefix |
| --- | --- |
| 2 / timeout | `02 || signer20 || V(round) || V(QC.version) || V(QC.start) || V(QC.round) || QC.hash32 || V(count) || ordered votes` |
| 3 / heartbeat | `03 || signer20 || V(round) || O(snapshot) || O(peers) || V(random_u32)` |
| 4 / acknowledgement | `04 || signer20 || V(random_u32) || V(round)` |

Each nested timeout vote is signer20, eight independently varint-encoded u64
limbs loaded little endian from signature bytes0..63, then unrestricted byte64.
The seven remaining signature bytes are inactive padding for this projection.
The outer timeout signature is excluded; nested QC signatures and vote order
are included. This says nothing about valid recovery IDs or cryptographic
signature canonicality.

A heartbeat snapshot is `O(stakes) || O(jailed) || V(evm_word) || O(three summaries)`.
Each summary emits its first word, second word, then hash32. Maps emit count and
ordered address20/word pairs; sets emit count and ordered address20 entries.
Absent and present-empty options differ. The API preserves supplied order; it
does not sort, deduplicate or claim to construct the native tree.

## Domain and proof boundaries

Read [PROOF.md](PROOF.md) for full function/caller addresses, the array/tree
induction, status8 short-circuit, exact sizing and multiblock hash composition.
The theorem assumes stable readable active fields, valid disjoint storage,
successful fresh allocation, truthful finite tree/count/parent/height metadata,
nonwrapping pointer arithmetic and serialized size `D+29 < 2^63`. Opaque calls
must preserve the stated live fields and escaped aliases. The imported `memcpy`
must satisfy ordinary exact-copy/frame semantics on valid nonoverlapping spans.
Malformed null-root/positive-count trees are a concrete excluded counterexample:
the target can emit a positive count and no entries while returning success.

The complete absorb/finalizer wrapper handles every full 136-byte block and
requires another padded permutation even at exact multiples. **Native identity
of permutation P with standard Keccak remains conditional on the credited
baseline [RE-005 action-signable evidence](../RE-005-action-signable-94/README.md).**
This packet does not claim a new formal equivalence proof of all 25 lanes.
Its Rust digest helpers reuse that existing MIT implementation. Signature
recovery, signing, proposer scheduling, selector0 and complete authenticator
integration remain outside this contribution.

The source exports timeout/heartbeat/acknowledgement preimage and digest helpers,
checked size functions, and borrowed heartbeat value types. It returns its own
length/allocation errors instead of inventing native panic payload equality.
The explicit claimed signer is required. Existing authentication methods are
unchanged; in particular, the old timeout recovery trait does not itself carry
that signer and is not silently replaced by these helpers.

## Evidence and validation

Start with [VALIDATION.md](VALIDATION.md), [PROTOCOL.md](PROTOCOL.md) and the proof.
Bulk native text is retained for independent inspection, not substituted for the
manual semantic argument:

- `scope.json`: 38 complete FDEs, 19,172 bytes, 4,655 instructions, including six
  complete immediate callers, both passes, iterator bodies, leaves and hash closure.
- `gnu/` and `llvm/`: independent full native exports; raw byte spans and
  instruction boundaries agree, with standalone LLVM LOCK grouped explicitly.
- `records.json`: PT_LOAD-backed extents, raw FDE/CIE records and complete call
  census. RELATIVE relocations require symbol index zero; `memcpy` is bound by
  GLOB_DAT import name, not inferred from a call-site label.
- `obligations.json`: 619 selected instruction pins and eight data spans.
  These are structural checks against manual proof obligations, not an emulator
  or an automated proof of the whole control/data-flow theorem.
- `fixtures/`: 534 independently derived pre-Rust value cases, from 52 to 7,368
  preimage bytes, including exact lengths135/136/137,271/272/273,407/408/409.
- `PRE-RUST-FREEZE.json`: original eight-file expectation freeze. The transparent
  [post-freeze correction](POST-FREEZE-PROOF-CORRECTION.json) adds only the missing
  memcpy premise after the first Rust draft; it reconstructs the original proof
  hash and leaves every fixture/expected byte unchanged.
- `build.py` / `driver.rs`: real three-package Cargo graph, fixed-width input-only
  frames, both profiles, retained outputs and ten compiled behavioral mutants.
  Expected preimages, lengths, names and digests are never supplied to the driver.

`corpus.py` extracts only the pinned existing MIT pure-Python Keccak arithmetic
helper and constants. It never imports or runs that provider's captured evaluator.
The expectation encoder and independent size equation preceded all new Rust.
An output match establishes agreement with those independently derived values;
it is not a native runtime observation.

## Reproduce

From the repository root, use fresh output paths:

```sh
python3 research/work-items/RE-008-consensus-other-preimages-94/verify.py --out /tmp/consensus-other-static
python3 -O research/work-items/RE-008-consensus-other-preimages-94/verify.py --out /tmp/consensus-other-static-opt
python3 research/work-items/RE-008-consensus-other-preimages-94/build.py --out /tmp/consensus-other-rust
```

The static verifier admits the whole SHA/size before private-snapshot disassembly,
regenerates two independent output trees and the frozen corpus, and checks
counterfactual bytes below the identity gates with fresh native decoding.
`--binary`, `--gnu` and `--llvm` select explicit input/provider paths. Recorded
defaults are GNU binutils2.47.20260726 and Apple LLVM21.0.0;
`native-providers.json` records executable identities. Native text formatting is
version-sensitive; exact export regeneration requires compatible providers.
`evidence.py --out NEW_DIR` and `corpus.py --out NEW_DIR` regenerate each portion.

`build.py --toolchain-bin PATH` selects an explicit Rust1.94.1 toolchain. The
default is the recorded macOS toolchain. It audits genuine manifests, ancestor
configuration and hooks, uses an empty task-local Cargo home, and invokes Cargo
offline/locked. It runs the existing actual-crate tests, the seven new integration
tests, checked-size unit test, Clippy and the frozen input-only corpus in both
profiles. Mutants copy the same three packages with their real manifests/lock,
changing only the new module. No fake workspace is used.

No broad repository `make test` or captured evaluator is required or claimed.
`MANIFEST.sha256` covers retained packet files; packet-local `.gitattributes`
stores all small gzip evidence as ordinary Git bytes rather than LFS pointers.
