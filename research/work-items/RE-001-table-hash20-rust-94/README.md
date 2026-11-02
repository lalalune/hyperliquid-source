# RE-001 / foundation: reconstruct the established fresh-20-byte hash math

- Target: node #94, 91,774,280 bytes, full SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Current base: `966865f1637a29ce75b019e1bf11d5529cc6f519`.
- Accepted native evidence: merged #1077, `RE-001-address-hash20-94` and
  `tools/address_hash20.py`, preserved unchanged.
- Outcome: independently authored Rust for the already established fresh-
  twenty-byte hash relation, with a real direct build and actual comparisons.
  No copied inferred source, new dependency, integrated node or full gate claim.

## Gap, native scope and ownership

The existing packet establishes exact fixed-domain math and compares captured
arithmetic against independent integer equations, but no Rust implements it.
This adds that missing implementation as one family, not independent items for
each word, rotation or final round. ASCII address parsing is a different contract
and is not copied or recounted here. No current Rust implementation overlaps
these native owners; the nearby keyed multiply-XOR work targets a different FDE.

The complete native disassembly denominator remains two actual FDEs:
caller `0x2840fb0..0x28410f5` (325 bytes / 83 instructions) and writer
`0x288e280..0x288e457` (471 bytes / 141 instructions), **796 bytes / 224
instructions**, in ELF virtual coordinates. Their complete old exports, raw
FDE/CIE records and hashes are unchanged. The new oracle authenticates the entire
capture, regenerates all accepted records and requires exact equality, including
both body hashes, initialization constants and selected fresh-writer boundaries.

The old bounded interpreter evaluates actual arithmetic bytes at
`0x288e3a4..0x288e3da` and `0x2841003..0x28410f0` using synthetic registers and
stack. Initial shuffles, the fixed two-word loop, fresh tail state and four-byte
tail selection are existing byte-bound specialized lowerings. **This is not
full interpretation or recovery of the generic writer's 471 bytes.** Other
lengths, incremental writes, nonzero initial tails and caller/table object ABI
remain outside the claim. The Rust exposes only two explicit seed words and a
fixed twenty-byte array, with a private independently chosen state representation.

All fixture words/messages are public synthetic values. No runtime seed,
credential, wallet material, address state or live dataset is retrieved. The
result is the table-hash relation only, never address derivation, signing or a
claim about production seed selection or cryptographic safety.

### Shared-dependency attribution

The established mathematics is SipHash-1-3, also implemented by Rust's public
`SipHasher13`. The standard-library source describes its default table-hashing
use: https://github.com/rust-lang/rust/blob/main/library/core/src/hash/sip.rs .
This public-source comparison is attribution context, not proof of the captured
node's exact Rust std revision, crate ownership or original build graph. Treat
these windows as candidate shared standard-library/dependency behavior; do not
count this bounded implementation as recovered first-party node code. No
first-party byte credit or completion gate is requested. This clarification was
added after independent implementation and does not copy public implementation
code into the Rust source.

## Established math and Rust implementation

The four initial state words XOR the two supplied words with the four captured
constants. Each eight-byte little-endian message word is XORed into the fourth
word, mixed once and XORed into the first. The final four-byte little-endian tail
is combined with `20 << 56` and absorbed the same way. The third state word
then XORs `0xff`; three mixes precede the final XOR of all state words.

The Rust independently expresses this relation with explicit `wrapping_add`,
fixed rotations, endian loads and a fixed array. It does not transplant bytes,
invoke an original hasher object, copy unlicensed inferred code or implement
unestablished generic writer paths. The accepted packet retains its algorithm
identification; no original Rust/library revision is inferred from it.

## Pre-Rust expectations and actual comparisons

Original commit `eec4a164` freezes `PRE-RUST-FREEZE.json` and the twelve-row
smoke corpus before `lib.rs` exists. That unchanged freeze was replayed as
`ae0d4767` when rebasing onto current main; no original assertion was rewritten.
The old interpreter source is unchanged. After the rebase, all expectations,
native records, actual builds and applicable repository checks were revalidated.
No previously shared CI prerequisite remains in this change because #1295 merged.

There are **20,756 comparison rows / 20,676 distinct seed-message pairs**.
The population contains the old 20,480 every-message-byte-position cases under
four explicit seed pairs, twenty zero/ff/tail boundaries and 256 deterministic
synthetic seed/message cases. Counts are not native captured invocations or a
complete enumeration of the seed/message space. The pre-Rust oracle took 2.197
seconds and every captured-arithmetic result agreed with the independent math.
Full input/expected hashes are frozen; long deterministic corpora regenerate in
the fresh output directory rather than being duplicated in Git.

The production Rust driver receives only IDs, explicit synthetic words and
message bytes. Expected hash answers remain in the external comparator;
ordinary `cfg(test)` code alone reads the frozen smoke answers. Rust 1.94.1
opt-level zero/three builds each match **all 20,756** answers and pass the
ordinary smoke assertion. Additions run with overflow checks enabled, so the
required wrapping is explicit. Identical optimized recipes produce raw-equal
own rlibs with no normalization. Pinned rustfmt and Clippy library/test builds
with warnings denied pass.

Three actually compiled Rust mutants change a rotation, put length in the wrong
byte or omit a final round. Each causes **20,756 mismatches** and fails the
actual compiled smoke assertion. Three private native edits change compression
rotation `0x288e3ad`, finalization rotation `0x284106a` and initialization byte
`0x204ec0`; their interpreted hash differs from the baseline
`639e355ae68c0100` for synthetic seed `(0,0)` and message bytes 0..19. The native
checker rejects each. These controls exercise the established scalar cut;
they are not claims about complete behavior of modified generic functions.

Oracle/controls use the separately authorized **offline Python captured-
arithmetic interpreter**. Do not describe this as no emulation. No native
captured node/visor, Unicorn, live network or chain operation is launched.

## Reproduce, results and remaining work

```sh
python3 -m unittest tests.test_hash20_rust tests.test_address_hash20 -v
python3 tools/hash20_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
make doctor verify catalogue-check reproduce
make test
git diff --check
```

Current-main focused validation passes **10 tests in 6.225 seconds**. The earlier
old-base focused result (10 in 5.373 seconds) is historical, not substituted for
current-main checks. Safe checks pass on current main. `build-result.json` keeps
actual compiler/linker/SDK, source/input hashes, recipes, profile/mutant outputs
and controls. `$REPO`, `$OUTPUT`, `$RUSTC` and `$LINKER` replace private path
spelling only, without masking code operands. Raw logs/products stay in the
fresh output folder. Full-suite state is separately recorded in `validation.json`;
pending does not imply pass.

The real standalone build is Rust 1.94.1, edition 2021, dependency-free `no_std`,
one codegen unit and warnings denied; it fabricates no original Cargo package
or workspace. The compiler is the repository's research pin, not recovered
node build provenance. Host arm64 macOS rlib reproducibility is not an x86-64
Linux byte match. Target raw/normalized match counts remain unmeasured. All
component gates remain unchanged under the new source-built-node accounting.
Before integrating this fragment, close static caller/seed ownership and generic
writer/data/ABI paths; do not retrieve runtime key values. A source-built network
node and its delivery checks remain separate, open work.
