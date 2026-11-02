# RE-012: node94 connect readiness, socket-error and cancellation boundary

The preceding first-request result can retain a pending descriptor. This packet
resolves the following ordinary-result boundary: registration versus resume,
pending versus query, the actual imported getsockopt request, zero versus
nonzero option/error payloads, and phase-dependent cancellation. It also follows
the cleanup helper's sentinel write before close: the apparent second caller
close is skipped under the stated ordinary-return/no-reentrant-alias premises.

Base966865f1637a29ce75b019e1bf11d5529cc6f519; node94 SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. The11complete FDEs retain3674bytes/1026GNU rows, including
supporting context; these are an explicit identity denominator, not recovered
function/byte credit. Exact addresses, tables, direct transfers, imported and
relative slots, and opaque references are in recipe.json/observed. GNU2.42 and
LLVM18.1.3 raw exports remain intact. LLVM's adjacent standalone LOCK prefixes
are joined only for the partition comparison, with every join recorded and
no omitted or masked bytes. Raw partitions are not claimed identical.

PROOF.md is the original pre-checker manual draft retained verbatim for the
freeze's identity. Its future-tense qualification checklist records the
pre-checker state; VALIDATION.json and the exact retained command receipts
describe qualification actually performed later. The manual relation is
conditional. TLS initialization/budget callbacks, allocator/locking/refcount
contracts, indirect error and waker callbacks, nonreentrant valid disjoint
storage and ordinary imported results are explicit premises. The TLS budget
projection additionally assumes its initialized flag and budget remain stable
across ordinary external callbacks except for the shown decrement/restoration.
No dynamic callback implementation or concurrency/liveness theorem is claimed.

24741synthetic mathematical expectations were frozen before check_relation.py:
15120poll-result projections,1280cancellation cases,30registration errors,
8281independent first/second reactor readiness pairs,30initialized-TLS budget
projections. They are independently authored aggregate-field expectations,
not captured target outputs. The checker uses separate bit-mask/struct-packing
relations and17wrong rules. Unusual numeric import returns test the literal
predicate and do not claim those returns occur under the documented ABI.
Only variant-defined fields are compared; unused error tails and padding are
not promised initialized values. A pending/ready flag alone is never accepted
as proof of an established TCP connection.

Reproduce with fresh output paths and an authenticated, non-executable artifact:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat with optimizedPython. Verification reads the retained observed records;
native/data/RELA/call corruption controls support the manual proof without
evaluating captured instructions. Root doctor/verify/catalogue-check/reproduce
results are recorded in VALIDATION.json. Fullmake test includes captured
instruction evaluators outside this run's authorization and remains NOT RUN.
No captured execution, networking, compiler/Rust/nativeABI equivalence, full
async/transport acceptance, hosted CI or new recovered-byte credit is claimed.

Prior transport-node-port-94, transport-socket-calls-94 and
RE-001-transport-integration-review-94 retain their credited census/context.
Author's PR1672 retains the earlier first-request relation. This packet does
not duplicate that outcome or depend on its open branch at runtime. Generic
MIT static evidence tools are reused from the author's PR1672/PR1607 with
target/recipe adaptations and explicit adjacent-LOCK partition comparison.
New proof/oracle/checker sources are independently authored MIT; imported bytes
retain their original rights. No unlicensed inferred source is copied.

Descriptive references: [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html),
[getsockopt(2)](https://man7.org/linux/man-pages/man2/getsockopt.2.html),
[epoll_ctl(2)](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html).
The imported names and numeric request predicates are bound independently to
the ELF rather than inferred from those descriptions.
