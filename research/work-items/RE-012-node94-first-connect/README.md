# RE-012: first configured IPv4 connect request in node94

The existing port and socket inventories identify arithmetic and call edges,
but explicitly leave their address data flow open. This packet follows one
fresh parent state through its actual connect future to the imported request:
the selected base port and either configuredIPv4 bytes or127.0.0.1 reach the
16byte native frame, with a network-order port. It also bounds the immediate
socket/connect adapter result and its ordinary close request.

TaskRE-012/transport, base966865f1637a29ce75b019e1bf11d5529cc6f519,
node94SHA-2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Addresses are linked ELF VAs, exclusive FDE ends. PROOF.md
states the fresh phase0, selector0..5, no-overflow, valid/disjoint storage,
TLS and ordinary import/copy preservation premises. The three complete
FDEs2037ac0/20487f0/3cd6330 retain7583bytes/1442native rows. This denominator
includes credited context; it is not a recovered-function or coverage count.

Port table/arithmetic/panics, import-call census and earlier fullfuture native
context are credited to transport-node-port-94, transport-socket-calls-94 and
RE-001-transport-integration-review-94. The new claim is their exact selected
value/copy correspondence, not another arithmetic or syscall census.

The21,312 mathematical records were frozen before check_relation.py:
18,372address cases and2,940ordinary-import result representatives. They
include bit0/high-bit distinctions, each IPv4byte value, all local indices
as credited arithmetic context, boundary fds and70errno representatives.
The checker uses a separate packed-integer/struct-packing relation; it never
interprets captured instructions or runs networking. Ten wrong rules must
disagree, and all65,536port byte encodings have an independent check.

Reproduce with Python3, GNU binutils2.42 and LLVM18.1.3, using an authenticated
non-executable node94 artifact and fresh output paths:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Verification reads retained observed records. Repeat with optimizedPython;
receipts and the frozen corpus must agree exactly. Native identity controls
support the manual argument, never a runtime equivalence claim. Actual root
doctor/verify/catalogue-check/reproduce and exact commands/results belong in
VALIDATION.json. Fullmake test invokes captured instruction evaluators and
is excluded from this static-only run; no hosted CI or compiler is claimed.

Future resume/retries/registration/scheduling, actual TCP establishment, OS
descriptor lifetime, TLS internals, native ABI, unwind and whole-component
acceptance remain unresolved. IPv6/listener/backlog paths are outside this
IPv4fresh request contract. Error115 preserves a pending fd; it is not proof
of an established connection. Mutableglobals and context callbacks are
recorded as opaque, not assigned runtime values. All component gates and
new recovered-byte credit remain unchanged.

Generic survey/verifier/binding/LLVM tools reuse the author's independently
authored MIT PR1607 sources with target/recipe adaptations, without runtime
dependency on another open packet. New proof/checker/expectation sources are
independently authored MIT; no unlicensed inferred source is copied.
Captured bytes retain their original rights. Linux manual ip(7),socket(2)
andconnect(2) support descriptive request terminology; numeric frames and
selected result predicates are bound to this artifact, not assumed from a
source-library label.
