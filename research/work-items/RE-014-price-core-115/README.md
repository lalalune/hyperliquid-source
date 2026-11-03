# RE-014 / RE-004: node115 post-helper scalar quote projection

Node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105896032bytes; base8fd8db680ec4bfef40996e5616bce3d5156d0b86. Component allocation:
assets / raw price and wei arithmetic. The bounded question is whether a
licensed historical scalar policy corresponds to this115 arithmetic suffix.
No source-function/type name, clock unit or full auction implementation is
established. All92component gates remain false; no machine-byte window credit.

## Observations, inference and boundaries

The actual FDE-described owner is `[0x3be5790,0x3be59f9)`,617bytes/147instructions,
body SHA-256 `c217f35544cc6b78e0fb52dbdd5df293aba55d854c0037c31470326ca3b451c1`.
The packet retains full GNU/Capstone exports, independent FDE/CIE records,
selected RIP constants and eight actual indirect-call sites through slot
0x64e6ac8. These are recorded static callers, not a complete dynamic call graph.
Source labels and full caller layouts remain unclosed. The price/auction names
are inference from historical structural leads, field use and numeric behavior.
Coordinates are ELF VAs; audit.json also records file mapping and raw records.

The interpreted suffix starts0x3be586d after a normal opaque helper return in
XMM0 and stops0x3be57ad after its common result-tag store. Inputs are the raw
binary64 low word, bucket at R15+0x10/R14, start at R15+0x28, floor at R15+0x38,
and output pointer RBX. Prefix time/metadata/round calls are identities only,
listed as unclosed in audit.json. None is executed or replaced with a stub.
A supplied helper-return word does not establish original helper reachability.

Observed scalar output relation, under the stated binary64 premises:
nonfinite/nonpositive elapsed maps to0; positive finite elapsed truncates with
u64 saturation. The unsigned start-floor borrow selects native tag0xc4. For
other cases, factor is max(1-elapsed/bucket,0), product is saturating-truncated,
then unsigned checked-add of floor falls back to floor on wrap. A zero bucket
is preserved: NaN/negative-infinite factors select0. The native factor>1.01
fallback is retained in the instruction model; for the qualified nonnegative
elapsed/u64 bucket domain it cannot arise from that factor calculation. Its
shared floor path can still be reached on addition overflow.

The Rust API is a new safe Result projection: native error tag0xc4 becomes E,
success0x1a2 becomes O/value; error payload bytes are excluded. Rust checks the
unsigned range before float arithmetic, unlike the native suffix order. Only
this normalized output is compared: FP status, exceptions, traps and ordering
are outside scope. Binary64 nearest-even/gradual-underflow premises and quiet
NaNs only; target MXCSR and runtime FP environment are not closed. Memory,
original result ABI, helper effects, lifecycle, valid input reachability and
whole-function equivalence remain unknown.

## Pre-Rust freeze and independent owned build

Freeze commitbc8bee97 precedes the new115 Rust component. The project's licensed
MIT scalar policy at5491d673 already existed and is explicitly reused. No
unlicensed inferred implementation was read/copied and no old addresses or
outputs were transferred. freeze-producer.py is a one-time pre-component
producer, runnable at that freeze commit. native.verify regenerates its streams
later. Full raw streams are retained in ignored work; hashes and12already-frozen
smoke rows are durable here. No expected stream is passed to the separately
linked, input-only client.

8312input tuples span signed zeros, subnormals, finite boundaries around2^53,
2^63/2^64, quietNaNs/infinities, zero/large buckets, start-floor error/equality,
rounded conversion and add-overflow cases, plus512fixed-LCG rows. The corpus
visits84of85selected-region instruction addresses; MOVSD at0x3be5997 was not
exercised. audit.json retains this unvisited address and the full denominator; this is a finite corpus result,
not exhaustive equivalence over every bit tuple. Four actual instruction
mutations change the normalized result. Unknown GPR/vector-lane reads, escaped
memory footprints, helper calls and returns fail closed in the task-local
wrapper. Existing shared instruction semantics are reused, not silently patched.

Research compiler: rustc1.94.1(e408947bfd),LLVM21.1.8,edition2021,
aarch64-apple-darwin; opt0/opt3, warnings denied. This is not the original node
build recipe. No invented Cargo workspace, dependency graph or lockfile. Own
rlib repeat, actual compiled semantic mutants and pre-frozen smoke tests are
recorded in rust-results.json and validation.txt after observed completion.

```sh
python3 research/work-items/RE-014-price-core-115/build.py --rustc <rustc1.94.1> --output work/price-core-new
python3 research/work-items/RE-014-price-core-115/audit.py --objdump <GNU-objdump>
python3 -m unittest discover -s tests -p test_node115_price_core.py -v
make doctor verify catalogue-check
make reproduce
```

Original freeze passed91.981wall seconds at10%active duty. The first builder
regenerated the native streams but exited1/87.606s before compiling because the
packet-path constant was missing. The constant was added. A second run completed native regeneration, all builds,
clients and smoke checks, then exited1/150.743s on a missing SHA constant in its
report expression. That constant was corrected. A separate recovery observer
checks the saved native hashes/source texts and actually re-executes the owned
clients/smokes/rlib repeat; it does not claim recompilation or another native
sweep. rust-results.json distinguishes this recovery from the failed CLI runs.
Raw failures and compiler outputs remain in ignored work. Later native changes
only add packet/identity constants and reject values outside the raw-u64 domain;
no valid-domain instruction semantics or expectation was changed.
Serial10%active-duty control does not promise a strict aggregate CPU percent;
priority changes are unavailable in this sandbox. No captured process, service,
network, chain, signing or private runtime state is used. Hosted CI is unobserved.
The same-base sibling full make test attempt stopped at1800s in file10/77;
first9completed. This is incomplete and never a full-suite PASS. Applicable
focused/build/reproduction results are recorded separately, with actual scope.
Next: establish caller field ownership and close the round/time helpers before
composing a complete price API. No full-component acceptance is requested.
