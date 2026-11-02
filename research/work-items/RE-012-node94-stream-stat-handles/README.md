# RE-012: node94 stream statistics keys and retained handles

The successful connect caller next constructs a stream aggregate beside its
retained registration. This packet follows that constructor into two separate
statistics registries, their endpoint/port/selector key, exact candidate key
checks, existing/new resource fields and the defined constructor placement.
It closes a pointer/key ownership boundary left open by the prior report and
counter packets; it does not implement a statistics reporter or hash digest.

Base966865f1637a29ce75b019e1bf11d5529cc6f519; node94 SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Eight complete FDEs retain5624bytes/1371GNU rows including
credited caller context. Constants, dispatch tables, initial ELF relocations,
direct transfers, mutable once-word reads and opaque references are recorded
separately. GNU2.42/LLVM18.1.3 raw exports stay intact; only adjacent standalone
LOCK prefixes are joined for the recorded partition comparison, with no byte
omissions or masks. This denominator is not recovered-function/byte credit.

The key is low32(address)|low16(port)<<32|selector<<48, with a zero upper byte
for the constructor's selectors0/1. The hash-update requests are LE64(selector),
LE32(address),LE16(port), totaling14bytes; hashing the packed seven/eight-byte
key is not this request transcript. A fingerprint match must also pass all
three key-field comparisons. Traffic and LZ4 use different tables and row
sizes. An existing entry returns its stored resources; a new entry requests
24/24/40bytes (traffic) or24/24/24bytes (LZ4), initializes three headers(1,1,0),
and then clones the three retained resources in order. Existing LZ4 fields
come from the cached tail. Partial-abort count writes and constructor padding
are explicitly distinguished from ordinary initialized outputs.

Two initial RELATIVE records, at5786480and5786530, occupy storage later used
as lock bytes after initialization. They are initial-data identities, NOT
runtime callback/lock values. Once words, table state and seeds remain runtime
inputs. A static file read is never used to assign those runtime values.

PROOF.md is the original prefrozen manual draft, retained verbatim so its hash
and pre-checker expectations remain reviewable. Its future-tense qualification
checklist describes that earlier state; VALIDATION.json and the exact receipts
record qualification actually performed later. Valid initialized tables,
ordinary locks/allocators/callees, stable disjoint storage and nonreentrant
callbacks are premises. Hash arithmetic, rehash/allocator lifetime, concurrency,
scheduling, original Rust type/Ordering/ABI and unwind remain unclosed.

33029independently authored mathematical expectations were frozen before the
aggregate-field checker:3106key requests,28592candidate comparisons,
1000literal clone-count projections,72handle fields,259constructor placements.
Twenty-two wrong rules must disagree. Arbitrary synthetic count/cached-tail/
clock patterns test literal field relations and do not assert live-state
reachability. Pointer-like integers are opaque tokens, not actual allocations.
No hash output is invented and no captured instruction/register is evaluated.
The defined projection excludes the two five-byte LZ4 padding regions and
six final bytes in the caller's152byte copy window.

Reproduce with an authenticated, non-executable node94 and fresh output paths:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat with optimizedPython; receipts and the Linux replay of the Windows
freeze must agree. Native/data/call/RELA corruption controls support the manual
argument rather than act as a semantic count. Actual root doctor/verify/
catalogue-check/reproduce results are in VALIDATION.json. Fullmake test includes
captured-instruction evaluators outside this static-only authorization and is
NOT RUN. No captured execution/networking/compiler/Rust/nativeABI/full hash or
whole transport equivalence, hosted CI, complete gate or new byte credit is
claimed. Constructor direction names remain0/1; inbound/outbound naming needs
independent consumer evidence.

Credits: traffic-recorder-instrumented-poll-94, lz4-stats-report-94 and
RE-001-lz4-counter-order-94 retain their consumer/counter results. Author's
PR1672/PR1685 retain first-request/readiness relations. Generic independently
authored MIT static tools reuse those earlier author packets/PR1607 with a new
recipe and target coordinates; no runtime dependency on an open PR is needed.
The new proof/oracle/checker are independently authored MIT. Captured bytes
retain their original rights. No unlicensed inferred source is copied.
