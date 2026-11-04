# RE-012: fresh Unix reverse component iteration and remaining-span view

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Foundation supporting
RE-012 node/output paths; all addresses ELF VAs, no byte masks or rebase.
New source/docs MIT; no inferred or public iterator implementation was copied.

## Gap, scope and incoming constructor

RE-012-node115-curl-body-helper leaves component iteration and borrowed-path
helpers opaque, although its suffix decision depends on their returned tag
and span. This contribution reconstructs the whole normal reverse-iteration
family for the actual **fresh Unix constructor** and states reachable through
reverse calls. It does not pretend to recover every corrupted or arbitrary
raw iterator state, forward-iteration mix or Windows prefix variant.

At `0x150210d` the real producer stores the input pointer/count at descriptor
+0/+8, prefix sentinel6 at +0x10, front/back bytes1/2 at +0x38/+0x39 and a
root byte at +0x3a computed from a nonempty input's leading `/`. RELATIVE
slots `0x64e0938 -> 0x5cab560` and `0x64e09b0 -> 0x5c8e8c0` bind the actual
reverse consumer and remaining-view helper. Exact constructor bytes and both
relocations are frozen. Original source type names are inferred roles, not
an asserted stable Rust layout or exact public dependency version.

| Complete FDE | Bytes | Selected role |
| --- | ---: | --- |
| 0x5cab560..0x5cab971 | 1041 | reverse component state transition |
| 0x5c8e790..0x5c8e8b3 | 291 | reverse body segment and consumed-count helper |
| 0x5c8e8c0..0x5c8eb16 | 598 | cloned-state remaining byte-span view |

Total export context: 1930 bytes / 513 instructions. These are not compiled
matching bytes or an implemented-byte percentage.

## Established data and state behavior

The reverse helper searches for `/` from the end, protecting one initial
byte when a root or initial relative `.` must be retained. It reports the
consumed count, numeric component tag and selected byte span. It uses tag10
for an empty or body `.` segment, tag8 for exactly `..`, and tag9 otherwise.
Repeated separators and interior `.` are therefore skipped, not returned as
normal components. It does not collapse `..` with a preceding normal name.

The outer iterator subtracts the helper's consumed count before testing the
component tag, stores the updated remaining length, and loops on tag10.
For the selected valid constructor this does not move the input start pointer
when consuming a body component from the back. Once only the protected start
is left, the iterator enters its terminal back state and emits tag6 for root
or tag7 for initial relative `.`. Subsequent calls return tag10. Empty relative
paths produce no component. Both the empty/current/parent distinctions and
subtraction-before-skip ordering are bound to original branch/store operands.

`remaining()` clones iterator data before trimming edge empty/dot segments;
it does not consume another visible component. Its original pointer/count
result may retain interior duplicate separators and dot syntax. For example,
a fresh `a/./b` remains `a/./b` as a byte view, while iteration returns b then a.
A fresh `a/.` has remaining view a. `./a` retains its initial current component;
`../a` retains its parent component. Initial root is protected from trailing
empty-segment trimming. This is a lexical byte contract, not filesystem
canonicalization, sandboxing, symlink resolution or Unicode normalization.

The independently authored safe library exposes borrowed byte slices and
logical variants only. It cannot represent invalid raw fields or malformed
pointer/length pairs. Native failure helpers, unreachable malformed-state
branches, inactive output bytes, full exception behavior and the original ABI
remain boundaries. Public std::path-style labels are interpretations supported
by the code and actual caller, not proof of an exact vendored revision.

## Real library qualification

qualify.py compiles a real no_std rlib at opt0/opt3 and links each probe with
`--extern`; it does not merely test an independent toy copy of the source.
The independent reference is the pinned compiler's pure Unix
`std::path::Components`, observing every reverse result **and the remaining
byte view before/after every step**, including exhaustion. OsStrExt admits
raw non-UTF8/NUL bytes without any filesystem operation.

The deterministic, deduplicated population covers all short structural paths,
longer slash/dot/a grammars, raw-byte/backslash classes, seeded long paths and
prefix-length boundaries. Reference observations are generated after initial
source authoring, explicitly not a pre-production-oracle claim. Full native
bindings precede qualification; actual counts/hashes and compiler commands
are retained in qualification.json. Six actually compiled mutations exercise
root loss, initial-current loss, parent/current confusion, body-dot retention,
remaining-view dot trimming and consumption of the protected separator.
Every mutant must return normally, preserve the independent reference output
and differ on a recorded input. Passing this finite comparison is not native
dynamic or whole-function machine-code equivalence.

The packet verifier authenticates target identity, full hashes/FDE/CIEs,
actual bindings and instruction anchors; GNU/LLVM/Capstone complete partitions
agree and readelf independently checks the extents. It replays all retained
exports, rejects two wrong/truncated captures, and changes one real byte per
anchor while bypassing only the full-file hash for that narrow control.
No captured code is executed, interpreted or emulated.

```
python3 -B research/work-items/RE-012-reverse-path-components-115/verify.py
python3 -B research/work-items/RE-012-reverse-path-components-115/qualify.py work/path-fresh /absolute/path/to/rustc-1.95.0
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-reverse-path-components/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-reverse-path-components/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-reverse-path-components/Cargo.toml -- -D warnings
make doctor verify catalogue-check reproduce
```

The initial 1100-row module smoke passed with a benign no_std-at-module warning;
final qualification instead links the real rlib. A mutation selector initially
expected an unformatted source layout and stopped after both production
profiles passed; only the selector was corrected, with the original run kept.
No expected or production behavior was changed to make the comparison pass.

validation.json records actual checks and reuse of the unchanged 583-file base
suite (zero nonzero exits, 25 explicit skips), not a new full-suite invocation.
Linux x86-64 library build does not imply Linux execution on the macOS host.
No live OS path operations, original source/ABI recovery, full caller closure,
compiled-byte identity or full-scope gate is claimed. This is a shared Unix
path primitive, not private first-party byte credit. Next: compose a qualified
path consumer with this iterator and byte validator after its allocation and
error-helper handoffs have been established.
