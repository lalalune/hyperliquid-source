# RE-005: Node115 signed scalar value, error and cursor

- Component: serialization; bounded RE-005, with RE-001 native boundaries.
- Target: Linux x86-64 node115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Original coordinates are linked ELF virtual addresses before load bias.
- Status: static observations plus an independent logical Rust reconstruction.
  No component gate is requested. No captured process or chain action ran.

## Question and result

The active source tree has no signed scalar implementation. Recover the
complete common value/error/cursor relation of the two 357-byte readers,
including their shared slow reader and diagnostic writer. This is a bounded
reconstruction gap, not a newly discovered application vulnerability.
Retired Node94 work such as PR1503 is not inherited evidence; this packet
uses fresh Node115 bytes and independently written Rust.

| Function | Extent | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Signed reader A | 0x2935ae0..0x2935c45 | 357 | 99 |
| Signed reader B | 0x5659e00..0x5659f65 | 357 | 99 |
| Shared unsigned slow reader | 0x58225c0..0x58226fc | 316 | 95 |
| Shared diagnostic writer | 0x5822700..0x582270e | 14 | 5 |

All 1,044 bytes and 298 instruction rows have independent GNU/Capstone
address-byte agreement. There are no byte or relocation normalization masks.
The four bodies are not compared Rust implementation windows and earn no
whole-ELF identity credit.
The two signed roots are the new 714-byte question; the 330 bytes of shared
helper context are retained for closure, not claimed as new coverage.

## Observed behavior

The signed roots compare the available byte count with eight. For at least
nine bytes, markers below 251 decode inline; 251/252/253 select 2/4/8 payload
bytes. Jump tables retain the exact branch destinations in records.json.
The endian byte is zero-tested, so every nonzero value selects byte reversal.
Successful reads advance pointer and reduce remaining count by encoded width.
They compute `(unsigned >> 1) XOR -(unsigned AND 1)`, then publish tag 0x12
and the signed result word. All 64 payload bits participate.

With fewer than nine available bytes, the root calls the actual RELATIVE
slot 0x64e6c38 -> 0x58225c0. That helper consumes an available marker before
checking the payload. A shortage records only the additional byte count;
it does not consume the remaining payload. Empty input requests one byte.

Unsupported markers differ by path. The root's fast error constructor uses
expected field 2; the slow helper uses field 3. Both roots map each tag-3
error field below six by adding six. The resulting expected fields are 8
and 9. Marker 254 produces actual 10, while marker 255 produces 12.
The fast rejection leaves the marker unread; the short-path rejection
consumes it. A generic unsigned-reader-plus-value-map would lose these
signed diagnostics. The safe Rust API preserves this difference without
inventing native padding or claiming an original enum name for every code.

The roots' error-writer slot is 0x64e6c40 -> 0x5822700. The slow reader's
0x64e7f78 slot reaches the same writer. All callee instructions in this
bounded family are retained; imported runtime/aggregate semantics are not
inferred from it.

## Caller evidence

caller-census.json retains three confirmed call instruction boundaries:
0x26e2c72 and 0x2706cf2 call A; 0x4ece8c2 calls B. All clear edx first.
The retained contexts of the two sibling owners at 0x26e2c30 and 0x4ece880
show an eight-unit counter addition stored before a limit comparison, before
the signed call, followed by a separate u32-shaped reader on success. This
does not establish the complete caller-owned budget policy. The
middle caller stores the signed result before its next scalar call.
These contexts bind use and little-endian mode, not domain field names.
The census covers raw E8/E9 and FF15/FF25 forms in .text, qualified against
full containing FDE instruction boundaries. It reports zero unresolved forms
and no RELATIVE slot pointing to either root. Other dataflow-derived indirect
references are outside that census; this is not a proof of every caller.

## Reproduce

Materialize the repository's pinned artifacts and imports first. Do not run
the captured node. Python uses existing ELF/FDE readers. GNU binutils and
Capstone are independent disassembly providers; versions and options must
be retained. Collection here used GNU 2.47, Capstone binding 5.0.7 from the
retained 5.0.9 distribution (core reports 5.0.1280), Windows x86-64 and
Python 3.12.1. No provider was installed by these commands.

```sh
python -B tools/node115_signed_scalar.py
python -B tools/node115_signed_scalar.py --collect --objdump /absolute/path/to/objdump --packet work/signed-native-replay
python -B research/work-items/RE-005-node115-signed-scalar/collect-callers.py --output work/signed-callers-replay
python -B -m unittest discover -s tests -p test_node115_signed_scalar.py -v
python -B -O -m unittest discover -s tests -p test_node115_signed_scalar.py -v
cargo test --offline --locked --manifest-path src/node115-signed-scalar/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-signed-scalar/Cargo.toml
```

Collection requires a new output directory. The verifier checks artifact
identity, complete FDE extents, body hashes, three helper relocations, three
jump tables and complete independent decoder rows. Corruption controls remove
or duplicate a row, substitute a byte/address, truncate GNU output and insert
a zero-length row; each must refuse. Seed1/UTC and seed314159/Pacific-Honolulu
replays emitted identical verifier results. The five physical evidence tests
passed in normal and optimized Python; six logical Rust tests passed in both
debug and release. Four compiled semantic mutants (diagnostic, cursor, endian and sign) were
refused by the Rust behavior tests. Two independent Linux-target rlib builds
of the own source were byte-identical. This is own-build reproducibility,
not equality to the captured ELF. These are focused results, not final-head/full-suite gates.

## Limits and next work

Initial make doctor passed. Initial make verify checked all six artifact
SHA-256 values, then failed while native Windows GPG imported the public key.
Signature authentication is not claimed; imports were checked separately.
Full mandatory final-head results and any original failures belong in the PR.
Do not weaken or bypass the GPG gate.

There is no native target-execution differential, original ABI/padding proof,
Rust-to-original byte identity, integrated node, network compatibility claim,
or completed component. The next integration question is the caller-owned
limit/error context and aggregate field schema. Preserve the fast/short
error and cursor relation when composing these primitives.
