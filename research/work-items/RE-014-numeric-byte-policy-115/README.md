# RE-014: node115 normal-return numeric-byte policy

Target node115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Parser FDE0x46aa760..0x46aab78:1048bytes/269 instructions. Full body/FDE/CIE,
RIP references, unique selected relocation writers, decimal-pair table and
formatter division operands are re-read. GNU-derived retained project records
are compared with the actual Capstone5.0.6 export and shared FDE parser here;
no new local GNU tool success is claimed. Full exports are context, not
implemented/matched-byte coverage.

The new dependency-free no_std Rust library reconstructs the conditional
normal-return byte/value policy: exact PURR/USDC maps to numeric0; canonical
#decimal saturating-adds100000000; @decimal requires1..99999999. Empty, signed,
noncanonical/leading-zero, overflowing and other byte inputs select the
fallback projection. Source/calendar/asset/protocol roles are not inferred.
The existing licensed project numeric_selector_static model is reused
unchanged as a native-operand-grounded oracle and is explicitly fingerprinted.
No shared tooling, imported evidence, pins or original source graph changes.

The new Selector enum has Numeric and CopySource variants. CopySource borrows
the exact input bytes; it supports composition into a later owned result.
Native allocation/copy/lifetime ABI and original result-layout semantics are
unclosed. The synthetic C probe writes tag/value/borrow-pointer/borrow-length
for validation only. Those pointer words describe our borrowed view, not a
native allocated pointer comparison. Normal opaque allocator/copy/compare
behavior is a premise of the original projection, not an implemented helper.
Original typed caller input constraints, UTF-8 provenance and namespace lookup
remain unknown; raw synthetic byte tests do not establish caller reachability.

## Reproduce

Python3.12/Capstone5.0.6 and direct Rust1.94.1 with the Linux x86-64 std target:

```sh
python tools/numeric_selector115_rust.py --rustc /path/to/rustc --out work/selector-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-numeric-selector/Cargo.toml
HYPERLIQUID_NUMERIC_SELECTOR_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_numeric_selector115_rust.py -v
```

Use a fresh output directory. Only newly compiled own ELF REL code is
interpreted. External data, unknown instructions, helper calls and own text
relocations fail closed. Captured input is rejected as object/compiler before
subprocess dispatch. No captured code, node service, signing, chain or network
operation is invoked. No ISA extension or shared-module change is needed.

33356 byte fixtures were frozen before Rust was authored in private WORK;
freeze.json identifies the exact expected stream and documents the limited
chronology evidence. Canonical boundaries, deterministic full-width samples,
malformed/raw-byte forms and saturation/leading-zero cases compare at all8
input byte alignments:266848 actual evaluations,0mismatches. The four explicit
probe words check logical values and full fallback view preservation. All7
separately compiled source corruptions and6 operative native operand/table
counterexamples produce differences and are rejected; repeated objects agree.
These are same-author experiments using the existing project static oracle,
not independent peer review or observed IO execution.

Own276bytes/75instructions is a different extent and logical ABI from the
native1048-byte function. No byte-identity/aligned-window metric or component
gate is claimed. Full parser object/allocator/error/helper closure, actual
namespace lookup/caller effects, original source types and node behavior remain
open. New code/docs MIT; existing project oracle reused under its root license;
original captured evidence retains its existing rights. Exact repository
checks and failures are recorded in validation.md.
