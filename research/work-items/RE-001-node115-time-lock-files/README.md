# RE-001: node115 time-lock filename collection and last-value handoff

This packet resolves a previously unmeasured node115 collector associated with
`node/src/visor_time_lock.rs`: how suffix-matching entries become an in-place
u64 vector, and which element a concrete caller consumes. It advances RE-001 /
node-runtime static reconstruction. This is code inside **node115**, not a
separate visor-binary task.

- Target: Linux x86-64 node115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Status: binary observations plus a conditional static proof; no gate change.
- Authorship: new proof, obligations and arithmetic independently authored.
  Image/export plumbing adapts the MIT-authored #2000 packet, with fresh #115
  ranges and records. No unlicensed inferred source was read or copied.

## New result

The collector uses a caller-supplied suffix; the retained caller supplies exact
`.json` bytes. After opaque path-component/conversion requests, the chosen slice
must end in that suffix. Its remaining prefix is unsigned decimal with an optional
leading `+`, at least one digit and a value no greater than 2^64-1. The proof
recovers the unchecked <=16-digit loop, checked >=17-digit loop, and raw error
precedence when multiplication overflows on an invalid current byte.

Accepted values retain input order and duplicates. They reuse the consumed part
of the original 24-byte-record allocation as 8-byte values. The output retains
the allocation pointer, triples element capacity and records accepted count.
The concrete caller consumes the **last accepted value**. A numeric maximum or
timestamp ordering depends on the opaque provider and is not established.

[PROOF.md](PROOF.md) gives the address-level argument, valid-input and helper
assumptions, cleanup boundaries and explicit unknowns. In particular, this does
not prove a complete basename converter, directory listing, filesystem schema,
time-lock expiration rule, timestamp unit, or supervisor protocol.

## Measured scope

| Role | Complete FDE, ELF VA | Bytes | Instructions | Semantic scope |
| --- | --- | ---: | ---: | --- |
| collector | `0x5961a30..0x5961e32` | 1,026 | 244 | candidate gates, suffix, decimal fold, compaction, output |
| caller context | `0x5a69e60..0x5a6a635` | 2,005 | 459 | `.json`, provider/collector handoff, last/empty selection |
| name-builder context | `0x5a69c10..0x5a69e57` | 583 | 124 | zero/nonzero name selection and visible path requests |

Total native export denominator: **3,614 bytes / 827 instructions**, with all
bytes and instruction starts agreeing between GNU and LLVM. FDE bounds are
independently confirmed by readelf. Context exports do not assert full-function
semantic closure. Records bind 28 instruction spans, 25 RELATIVE slots, the
actual `bcmp` GLOB_DAT import, 13 literal/Location records, every explicit call
and a limited incoming-call census. No normalization masks are used.

## Reproduce

Use materialized pinned Git LFS inputs, Python with Capstone5.0.7, GNU objdump/
readelf and LLVM llvm-objdump on PATH. Observed environment: macOS arm64,
Python3.14.7, GNU binutils2.47.20260726, LLVM18.1.4. From the repository root:

```sh
python3 -B research/work-items/RE-001-node115-time-lock-files/export_disassembly.py
python3 -B research/work-items/RE-001-node115-time-lock-files/verify.py --controls
python3 -B research/work-items/RE-001-node115-time-lock-files/algebra.py
python3 -B -m unittest discover -s tests -p test_node115_time_lock_files.py -v
make doctor verify test catalogue-check reproduce
(cd research/work-items/RE-001-node115-time-lock-files && shasum -a 256 -c MANIFEST.sha256)
```

The exporter authenticates the whole target, then gives native tools a private
byte-identical snapshot. Verification checks full-image identity, body hashes,
complete independent exports, FDEs, instruction obligations and data/call
bindings. `controls.json` records 73 rejected in-memory corruptions with the
whole-image, body-hash and export guards deliberately bypassed. Separate tests
exercise those three integrity guards and truncated input. Captures on disk are
never modified.

`algebra.json` records all256 ASCII byte classifications,70 boundary decimal
steps,256 overflow/current-byte classifications,8,256 compaction inequalities
and five actual operand counterfacts that change the extracted relation before
rejection. These finite checks support the proof; they do not execute or emulate
the target or establish runtime equivalence. Exact validation results and raw
command output are retained in `validation.json` and `validation-logs.json.gz`.

## Original gap, overlap and limits

Before this contribution the current tree retained the source path in an
inventory, without these function semantics. The after-state adds target-bound
ranges, a reproducible static argument and corruption controls. The all-state
PR/history audit is in `overlap.json`; immutable heads and file-snapshot hashes
are in `overlap-snapshots.json.gz`. Prior #9/#37/#1123 and integration #1151 only
inventory this source path. Their drift work is credited, not claimed again.
Public dependency reconstruction in #2050 is separate; no library implementation
or dependency-matching credit is claimed here.

No captured binary/emulator, live node, user file, network/chain action, signing,
wallet or paid dataset is used. No Rust implementation, source-built byte match,
whole-function equivalence, completed component or hosted-CI success is claimed.
All imported artifacts/pins and reconstruction gates stay unchanged. The next
useful question is to close `0x15623e0`'s provider ordering and entry construction
before interpreting the caller's last value as the latest time-lock timestamp.
