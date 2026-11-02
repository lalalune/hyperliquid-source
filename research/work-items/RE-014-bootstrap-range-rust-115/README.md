# Node115 inclusive bootstrap range entry

RE-014/RE-001, node-runtime. Base8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Target node115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
New target-specific evidence, not a release-label migration of node94.

At ELF VA5a88391, R15 points to target T and R14 points to inclusive raw lower L.
The subtraction must have no borrow and difference>=30001 to take5a88d17.
Otherwise L is stored to state+288. L>T continues at5a883c4 (unclosed).
L<=T joins5a83026: last=min(T,saturating(L+99)), stored to state+290.
Equality therefore produces a one-element range, not the historical94 equal
branch. The old current+1 expression must not be transplanted here.
This proves a difference bound, not a total30000-block/network policy.

The complete FDE binding (28357bytes/4774instructions), raw selected23instructions,
source Location RELATIVE relocation at64b92e8 (node/src/nv_stream.rs:412:17),
input/output roles and raw cold call are recorded in JSON. FDE binding does not
recover the entire large future or its source ownership. Only the selected
input pointers and state writes are qualified; their initialization/callers,
whole object ABI, async states, request side effects, cold helper formatting,
panic/unwind and reversed-continuation effects remain unclosed.
ESI53 does not independently establish a rendered string length or message.

Before new115 Rust source,53038 distinct raw u64 pairs were interpreted from
actual instructions and frozen by input/output hashes. Full TSVs remain in
ignored work and are deterministically replayed, not supplied to the Rust
client as expected answers. Five actual instruction corruptions are detected.
The retired94 logic preexisted and is explicitly disclosed in FREEZE.json.
No inferred unlicensed source was copied. No captured process/helper executed.
Corrected freeze exit0,64.718wall seconds under10% active duty. The first attempt
failed62.974wall: changing a later ADD99 did not affect the ordinary selected
branch (which uses the SUB-99 result). That negative result was retained; the
corrected mutation changes the actual SUB immediate and is detected.

Reproduce from root: `python3 tools/bootstrap_range_115_freeze.py work/range-new`
with Capstone5.0.6, Python3.12.14 and the authenticated existing115capture.
Output must be new. Replaying after implementation reports source existence
truthfully; all semantic records/hashes must match the pre-Rust freeze.
The bounded evaluator rejects calls, unknown instructions and unqualified memory.
No component gate, compiled machine-byte or whole-node equivalence claimed.

## Independent Rust reconstruction

Freeze commit94620e3b precedes new115Rust. `src/node115-bootstrap-range` is a real
standalone no_std component built directly with pinned rustc1.94.1 e408947bfd,
LLVM21.1.8, aarch64-apple-darwin, edition2021, codegen-units1, overflow checks on,
opt0/3 and warnings denied. No dependencies, Cargo workspace, build script or
lockfile is invented. Exact commands/compiler/source/ownarchive hashes are in
build-result.json; local repo prefix is redacted as <repo>. This compiler is a
research pin, not recovered original build provenance.

Both profiles match all53038 native rows. Twelve frozen native smoke rows pass
per profile. Five compiled mutants yield7/14067/230/613/4950 mismatches and all
fail native smoke assertions. Own opt3 rlib repeat is raw-identical. Builder and
fresh actual-instruction replay passed exit0,127.710wall seconds at10% duty.
No target/source machine-byte comparison or normalization is claimed.

Reproduce: `python3 tools/bootstrap_range_115_rust.py --rustc <rustc1.94.1>
--output work/range-build-new`. The native replay checks the original frozen
hashes before invoking Rust; the separately linked driver reads inputs only.
Original raw generated input/output/compiler/mutant logs remain in ignored work.
The full corpus is generated rather than duplicated in the PR; native freeze
hashes and compact smoke data are committed for review.

The enum ReversedContinuation reports only the selected route. Target's lower
store on that route is recorded by native evidence; subsequent memory/state
behavior is not reproduced by this scalar API. Newinterface is not original ABI.
No helper, captured process, network, thread, wallet or signing operation ran.
Rustfmt and Clippy library/tests passed. Four focused Python tests passed in
4.766wall seconds. make doctor/verify passed with29importedfiles/pins, active115
andvisor signatures,29packetmanifests/464entries and no grandfathered rows.
The initial combined command exited2 after61.558wall because the pre-Rust packet
changed generated inventory counts while README/banner had not been regenerated.
After staging the new115component and running make catalogue, catalogue-check
passed exit0 in24.408wall. Generated counts only; all gates remain false.
Nonfatal xcrun cache permission warnings and doctor's absent optional rustup/
Ghidra toolchains are retained; direct pinned Rust builds above actually passed.
Final reporting/packet manifest edits are checked separately. Full make test and full
make reproduce are not run under the operator's resource restriction; do not
interpret bounded replay or merge as a full-suite PASS.
Next: recover initialization/caller and remaining continuation only with fresh115
bindings. All unfinished component gates stay false.
