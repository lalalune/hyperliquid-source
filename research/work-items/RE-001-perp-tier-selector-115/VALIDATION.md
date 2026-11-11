# Qualification and limits

Final pre-Rust seal `1de14ed03dc45c5e2c1e1e1ea8b4d7e6588843d4`
freezes actual instruction inputs/results, evaluator, contract and full byte
witnesses before source authorship. The earlier1,513-row prefix observation is
preserved at836753bd8 and an owned external copy. It stopped before lookup;
the final4,015-row profile instead closes the actual283-byte search body and
uses valid bounded sorted ring storage. This scope/domain change happened
before Rust and is not an adjustment of expected outputs to fit the source.

Freeze passes in54.344s:4,015 distinct tuples,682 bytes/192 selected starts
all visited,2,264 genuine helper CALL/RET rows,24 actual output-changing COW
mutations and six additional rejected corruptions. Both full FDEs retain703B /
197 instructions, exact bytes, CIE/FDE and GNU/Capstone agreement. The 21B /
five omitted instructions are unreachable alignment and initializer/diagnostic
call or post-initializer continuation. The search helper has no additional
calls or external branches. The native oracle supplies no helper return.
Initializer and diagnostic remain exact pre-CALL frontiers. No original global
content, constructor completion, concurrency, diagnostic/unwind or native ABI
is claimed. Pointer identity retains object/cell/byte-offset; semantic changes
are not masked. Unused ring capacity and other inactive storage stay unknown.

Direct Rust build/comparison passes in519.928s. Opt0/3 and same-path opt3
rlib/output repeat each match every one of4,015 complete raw rows. All101
client cases from the unchanged sealed expectations pass. Sixteen separately
compiled semantic mutants finish their streams normally and differ in
316/1245/545/617/39/405/48/42/51/135/590/36/276/713/1493/1393 rows, and
all fail the client fixture with ordinary exit101. Source ring lookup uses
safe binary search in logical sorted order; for the qualified unique keys it
preserves the original two-span search's successful physical location. The
caller's unused miss insertion position is not exposed. No original compiler,
Linux target execution, ABI or compiled target-byte equivalence is asserted.
Host research uses macOS arm64/rustc1.94.1/edition2021, without external crates
or an invented Cargo graph. Separate-directory build repeat is unmeasured.

Exact source/driver/fixture/input/result hashes are in rust-results.json;
its full original command receipt is losslessly archived as named there.
All19 raw synthetic comparison streams and192 command stdout/stderr files
are also archived. Only owned directory prefixes in command logs are replaced
with <work>, with separate projection hashes and unchanged original local logs.
Gzip archives use mtime0, with raw payload hashes. The full native-control
witness archive is byte-equal to the pre-Rust Git record; its readable summary
omits duplicated large input arrays only. The101-case Rust fixture archive is
byte-equal to the original tested source. Expanded fixture stays at its exact
original ignored path; replay prepares and checks it before compilation. Fresh
preparation and repeat passed separately; all original actual build/compare/
transport function ASTs remain unchanged. Packaging only makes evidence fit
review budgets; it does not alter source, goldens or compared values.

The final serial389.938s scoped run passes seven focused tests, rustfmt,
Clippy with warnings denied,12 packet-integrity tests, make doctor, make verify,
make catalogue, make catalogue-check and actual make reproduce. Exact exits
and elapsed seconds are in checks.json. Only catalogue generation/check uses
the already-submitted #2655 snapshot helper for its measured repeated-read
blocker; both revision/hash identities and scope are explicit. Baseline helper
is restored before reproduce/submission. No duplicate helper fix or unmodified
head local catalogue result is claimed. New source/packet README were staged
before generation. Final manifest, archive/receipt/source/fixture/stream checks
are separate from this scoped run.

One assets implementation path is added. Base has560 tracked top-level packet
READMEs despite stale generated559; this one new packet yields561. Rust areas
34->35, Cargo manifests stay19. All92 gates and byte registrations remain
unchanged. Original static packet #2252, shared tools, captured artifacts,
imports and old tests are preserved. New source/docs are independently authored
MIT, with no unlicensed inferred source inspected or copied. No captured ELF
process, Unicorn, live service, signing, wallet or chain action is used.

First thirteen fresh sibling heads have observed exact-tree full upstream CI
success, explicitly shared evidence rather than this head's result. Full local
make test is not claimed; this PR's own full upstream CI is pending separately.
No merged integration tree, full metadata validity, reachable original caller,
complete container/global construction or source-built node is asserted. The
bounded source API's None refusal is an own policy, not a native malformed-input
response. Heavy local processes run serially under approved duty0.10 active-wall
control, not a guarantee of aggregate10percent CPU.
