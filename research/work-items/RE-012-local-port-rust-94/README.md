# RE-012: reconstruct node94 local-validator port arithmetic in Rust

- Component: transport / net_utils, one complete six-base arithmetic family.
- Target: node94 Linux x86-64, 91,774,280 bytes, SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Source base: 966865f1637a29ce75b019e1bf11d5529cc6f519.
- Scope: valid selector 0..5 and local-validator index 0..255; ordered
  multiplication/addition overflow and port success. No networking, address
  lifetime, async caller, non-local branch, captured unwinder or original ABI.
- Existing evidence is credited, not re-counted:
  research/work-items/transport-node-port-94 (merged #199) already establishes
  ten sites, bases, table/dispatch shapes and panic locations. #1672 separately
  studies the fresh configured IPv4 call corridor. This packet implements only
  established local arithmetic and closes #199's three unchecked byte-width
  inferences; it does not re-claim either caller or socket census.

## Before and after

Before: static equations exist but no Rust local-port component; three index
widths are explicitly inference only. The oracle was generated locally before
writing Rust. frozen-before-rust.json retains its canonical row hash and full
owning FDE hashes; this is local generation order, not a pre-source Git commit.
Existing reference material was not copied into the MIT source.

After: src/node94-local-port/lib.rs independently implements the six numeric
selectors and checked u16 arithmetic. checked_mul executes before checked_add,
with distinct panic classes. u8 and the safe six-variant selector express the
qualified input domain, not a recovered packed target enum layout. Returned
port values and panic class are compared; exact panic text, unwind frames,
panic allocation, OS/network effects and code-byte identity are excluded.

The target and source both produce success for index 0..61, add overflow for
62..65 and multiply overflow for 66..255, for every one of the six bases
4001,4002,4003,4004,3998,3999. The first overflow is retained. This is the existing
target behavior, including a panic rather than a returned port error.

## Reproduce

From the repository root with authenticated inputs and the normal Python/tool
environment (Python 3.12.14, GNU objdump 2.47.20260726, Apple LLVM 15.0.0,
Capstone 5.0.6 in the observed run):

    python3 tools/node_port_native.py --output work/local-port-native
    python3 -m unittest tests.test_node_port_native -v
    python3 tools/node_port_rust.py --rustc "$RUSTC" --output work/local-port-build
    "$RUSTFMT" --check --edition 2021 src/node94-local-port/lib.rs src/node94-local-port/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-local-port/lib.rs --emit=metadata -o work/port.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-local-port/lib.rs --emit=metadata -o work/port-test.rmeta -D warnings
    make doctor verify catalogue-check reproduce
    make test

RUSTC/RUSTFMT/CLIPPY select the pinned actual 1.94.1 binaries, not an installing
rustup shim. rustc -Vv is retained in build-result.json. Output directories must
be new. $OUT and $RUSTC in its argv list denote the chosen output directory and
compiler; "." denotes this repository root. The input-only driver receives
selector and index only, never expected values. No crates, arbitrary dependency
versions, synthetic root workspace or captured executable wrapper are added.

## Native evidence and closure

The producer authenticates the whole input, re-establishes all ten old
table/dispatch/panic Location and relocation bindings using the existing static
producer, then follows the actual arithmetic instruction corridors with the
separately authorized Python evaluator. Numeric coordinates are original VAs.
It stops at success or the resolved panic stub, never executes a panic helper.
Base selection is statically bound and supplied as a precondition to these
corridors, not executed as part of each arithmetic trace.

All five variable-base sites x six bases x 256 indices plus five constant-base
sites x 256 indices give 8,960 native comparisons, reducing consistently to
1,536 distinct selector/index expectations. The canonical native rows and full
FDE hashes are retained in frozen-before-rust.json; vectors are committed in the
Rust directory. All 76 visited arithmetic instruction starts/sizes/raw bytes
agree independently with Capstone; visited-instructions.json and selected full
GNU/LLVM listings retain context. This does not assert that 76 instructions
cover the whole owning functions or supply a component denominator.

At 0x22c54e5, 0x438f1ed and 0x47b4aa5, the actual byte loads, SHL8, conditional
zeroing and SHR8 are interpreted for both valid tags 0/1 and every byte index:
1,536 width cases. Tag1 reaches multiplication with the original u8 value;
tag0 clears the value and skips multiplication. The other seven sites'
immediate MOVZX byte instructions are already checked by the credited producer.
This closes the previously unchecked width premise without assigning endpoint
types or roles to invalid tags.

The existing evaluator rejected 16-bit MUL. The smallest local subclass handles
only observed unsigned MUL16, preserving upper register words and defining only
CF/OF; the complete 65,536-value low-word domain with multiplier 1000 is checked.
No shared evaluator changes or general new emulator are claimed. Three private
actual instruction mutations change stride, JO and JA: 61/256, 256/256 and
66/256 native outcomes differ. No original capture changes.

## Build and comparison results

Both real Rust opt0 and opt3 builds match all 1,536 frozen outputs. The component
unit test checks every selector at success/add/multiply boundaries. Three real
compiled mutants (stride, add and selector4) differ on 366,372,62 rows.
Two opt3 rlibs with the same basename are raw-identical; no byte normalization.
An initial experiment with one.rlib versus two.rlib differed because archive
member basenames differ; initial-archive-name-difference.json preserves that
negative result rather than counting it as reproducible.

Pinned rustfmt and Clippy library/test checks pass. The focused tests additionally
exercise corrupted oracle admission before invoking any compiler. The initial
new admission fixture had a missing import/incorrect mock and was fixed; target
expectations and comparator results were unchanged. Actual final focused and
whole-suite state are reported in validation.json and the PR, without treating a
running full suite as passed. Required safe gates pass.

## Remaining gaps

No original Rust ABI, dependency version, full calling context, equivalent panic
runtime, full-function code match, whole ELF, peer synchronization or Docker node
claim. Imported pins and original static packets are preserved. No catalogue,
first-party byte-credit or milestone gate changes are requested. Next join the
qualified scalar to an established source-built endpoint owner and transport
configuration once caller layout/lifetime is independently closed.
