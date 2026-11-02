# RE-012: first post-connect greeting request bytes

The configured IPv4 connection caller2037ac0 copies an original two-byte word,
then serializes it through28c0b90→28c14f0→25599e0/2559a40 before invoking its
frame writer. This packet closes that previously unbound payload boundary:
the three serialized bytes are A,B,0, where A/B are original parent+201/+202,
retained at+1f0/+1f1. The29byte diagnostic label is not the transmitted payload.

Base966865f1637a29ce75b019e1bf11d5529cc6f519; node94 SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280bytes. Six complete FDEs retain11315bytes/2172GNU rows, including
credited caller/wrapper/writer context. Raw GNU2.42/LLVM18.1.3 exports, FDE/CIE,
initial RELA, selected immutable data and direct call identities are retained.
Only adjacent standalone LOCK prefixes can be joined for partition comparison;
no bytes are omitted or masked. Identity rows are not semantic coverage credit.

The size pass begins at0 and returns3. The writer requests3bytes and stores
each source byte unchanged followed by a literal zero; the three capacity
checks require no growth with cap3/len0. The success vector passes through the
credited wrapper stores into the caller's actual writer pointer/length fields.
The credited raw framing rule produces the exact eight-byte REQUEST buffer
0000000300 A B 00. This is a buffer construction, not observed socket delivery.
The size helper's otherwise redundant source-byte comparison does not validate
or normalize B: its flags are overwritten before the next conditional branch.

Credit transport-tcp-frame-write-94 for compression/header/chunks/defaults,
RE-001-string-result-wrappers-94 for wrapper output stores, and the author's
PR1672/1685/1697 for address/readiness/stream construction. No general frame
writer, wrapper, enum schema, timer or message decoder is reclaimed here.
The carried60.0 withflag0 selects the already established20.0 chunk default;
that existing fact appears only to make this request reproducible in context.

PROOF.md is the original manual draft before the checker. Its future-tense
qualification checklist remains unchanged for hash replay. Actual later
qualification is recorded separately in VALIDATION.json and receipts.
65553independent pre-checker mathematical expectations include all65536raw
byte pairs and17size-counter boundaries. Twelve wrong aggregate rules must
disagree. Arbitrary raw byte values test literal projection, not the validity
or live reachability of original Rust fields. No instruction/register evaluator,
target invocation, invented ABI or external model is used.

Reproduce with a verified non-executable node94 and fresh output paths:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimizedPython, compare exact receipts and Linux expectation replay.
Root doctor/verify/catalogue-check/reproduce results are in VALIDATION.json.
Fullmake test includes unauthorized captured-instruction evaluators and is
NOT RUN. There is no hosted CI, compiler/Rust build, full transport or native
ABI equivalence, accepted gate or new recovered-byte claim. Stable disjoint
storage, ordinary preserving helpers and allocation success are premises.
TLS arms, error/unwind/lifetime, writer polling, actual socket write, timeout
expiry, retries and response parsing remain unknown.2049950/204b040 intake is
explicitly excluded. New proof/oracle/checker and reused generic static tools
are independently authored MIT; captured bytes retain original rights. No
unlicensed inferred source is copied.
