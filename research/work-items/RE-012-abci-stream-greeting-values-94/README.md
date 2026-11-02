# Complete supplied-reader ABCI greeting values, node94

This packet establishes the conditional ordinary-return value, active error
and Reader-state relation of `0x4674820..0x4674b45`: all six outer variants,
all three nested variants, byte vector, three signature-map readers and their
complete insertion/split/cleanup closure, and the owning three-record arm.
It also qualifies the supplied caller `0x471b880` only when EDX=0. The work
fills an RE-012 peer-protocol value gap; it does not claim network/session
compatibility, framing, authentication, startup integration or a progress gate.

The target is inert node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. No captured code is executed or emulated. This is a pre-code
packet: no new production Rust, client or build qualification exists yet.
The later source proposal requires a separate admission gate.

Review the contract and proof before the bulk exports:

* [CONTRACT.md](CONTRACT.md): complete logical grammar, active errors, state
  changes and explicit canonical-u64 Reader/memory/import premises.
* [PROOF.md](PROOF.md), [TREE-PROOF.md](TREE-PROOF.md),
  [CALL-FRAMES.md](CALL-FRAMES.md): complete operation composition, map relation
  and owner cleanup, exact call/frame boundary and excluded unwinding.
* [PROTOCOL.md](PROTOCOL.md), [SOURCE-PLAN.md](SOURCE-PLAN.md): future input-only
  comparison protocol and proposed actual merged-provider integration.
* [VALIDATION.md](VALIDATION.md): actual static checks and their limits;
  `validation.json` and `VALIDATION-RUNS.json` retain the receipts.

The important recovered behaviors are observable together. A u64 invalid marker
has expected category2 on the strict `remaining>8` fast branch and3 on the slow
branch; only the slow branch consumes the marker on failure. A representable
over-limit charge is stored before error, while overflow has no charge store.
Map reservation96 per row is refunded before the actual85-byte charge, retains
unprocessed reservation on failure, and charges duplicate wire rows even though
the last equal key replaces its value without increasing distinct length.
The final signature byte accepts all256 values. Nested tag2 owns three records
of two scalars plus2048 bytes each; the returned native word is a pointer.
The EDX=0 caller returns consumed only on success and permits trailing bytes.

These are conditional proofs. The entire Reader limit tag must be u64 0 or1;
merely setting its low byte is insufficient. All imported copy/compare and
allocation/free calls require explicit successful/frame semantics, including
count0 memcpy with destination sentinel1. Created map invariants are proved
from empty roots, not supplied as an opaque insertion assumption. No arbitrary
native tree, allocation failure, foreign mutation, callback timing, panic,
personality, unwind, Rust layout or allocator-identity theorem is claimed.

The static scope is30 whole FDEs/19,082 bytes/4,317 rows:28 core bodies/17,147
bytes plus the passed-but-unused byte leaf and full caller context. The explorer
sibling466eb70 is excluded. All4,280 non-padding instructions,11 data spans,
7 dispatch tables,17 register-loaded calls and9 LSDA records are bound; the
complete80,300-entry RELA census excludes writes into selected code/data.
GNU and LLVM agree on full native byte partitions. Decoder agreement and
negative controls bind the evidence; the manual proof establishes semantics.

`oracle.py` uses mathematical integers and flat dictionary relations, independently
of native B-tree shape and before later source. The18,290 frozen-input candidate
frames include17,812 core Reader cases and478 selected-caller cases, all8 success
tags and5 active error kinds. Inputs cover all marker/recovery bytes, fixed-field
shortages, strict length thresholds, nonminimal scalars, reservation/limit/overflow
boundaries, duplicate order, all12 full-node gaps and deeper cascades. Finite
coverage is not a proof of all inputs. `certificates.py` independently checks
finite index identities supporting the written induction; it does not interpret
machine instructions. The corpus metadata never enters the proposed client.

Reproduce from the repository root, with the exact capture already present:

```sh
python3 -B research/work-items/RE-012-abci-stream-greeting-values-94/verify.py \
  --out /new/greeting-static-normal
python3 -B -O research/work-items/RE-012-abci-stream-greeting-values-94/verify.py \
  --out /new/greeting-static-optimized
```

`--target`, `--gnu` and `--llvm` accept explicit provider paths. Recorded defaults
are Homebrew GNU objdump2.47.20260726 and Apple LLVM21.0.0. Raw exports and provider
metadata are version/path-sensitive; arbitrary decoder versions need not produce
byte-identical text. Each provider reads an authenticated private0400 snapshot
named `hl-node`; no text/path rewriting is applied. Python code requires only
its standard library and the two hash-pinned merged ELF/DWARF parsers. Raw gzip
files are ordinary Git blobs via packet-local `.gitattributes`, not LFS pointers.

Prior credit is substantive. Merged [PR1162](https://github.com/lalalune/hyperliquid-source/pull/1162),
retained in [stream-msg-codecs-94](../stream-msg-codecs-94/README.md), established
the outer/nested partition and explicitly excluded the inner readers/maps and
caller. This packet closes those exclusions and the complete owning record arm;
it does not allege the older word-sized observation was a logical-type claim.
The merged [varint](../RE-005-bincode-varint/README.md),
[slow-width](../RE-005-bincode-slow-widths/README.md) and
[Reader source](../RE-005-bincode-reader-rust-94/README.md) work supplies scalar
prior evidence and a potential source provider. Open
[PR1365](https://github.com/lalalune/hyperliquid-source/pull/1365) independently
qualifies related wrapper state; it is credited, not used as a pending runtime
dependency. No unlicensed reference source was copied. The target and prior
packets are one project lineage, not independent confirmations of native truth.

The coordinator's retained live intake through PR1692 found no known declared
scope takeover for this operation; that is a bounded snapshot, not repository-wide
absence proof or a substitute for a final ownership check before publication.
Deferred work remains instrumented caller effects, greeting-to-session behavior,
message encoding, transport/authentication composition and actual source qualification.
