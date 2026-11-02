# Visor digest value closure

This packet closes the initialized one-shot digest dependency at `396750`:
Keccak-256 over the bytes supplied by an opaque reader, with the wrapper's raw
error result, output-store order and cleanup premises stated separately. The
complete four-function proof covers 3,612 bytes / 877 instructions and credits
the existing RE-013 lifecycle evidence and PR45. It supersedes that packet's
inferred SHA-256 label for this helper while preserving the old file unchanged.

The intended source outcome is qualification of the **existing merged MIT**
`src/node94-action-signable::keccak256` provider. No duplicate Visor hash API or
wrapper is added. This pre-code phase contains no new Rust client and makes no
compiled-provider or target-runtime claim. A separate source/build gate is
required before qualification code or compilation.

Read [PROOF.md](PROOF.md) for all 25 lanes, generated round constants,
136-byte rate, delimiter/padding, full-block/tail/empty cases, output and error
layout, imported-call frames, and the leaf red-zone assumption. The theorem
depends on a stable valid reader result, nonaliasing storage and ordinary
helper returns. It does not establish filesystem behavior, arbitrary streaming
states, generic squeezing, signature verification or cryptographic security.

[CONTRACT.md](CONTRACT.md) fixes the existing-provider scope and later source
admission. [PROTOCOL.md](PROTOCOL.md) separates the future input-only client
from the comparison harness. The independent bit-plane oracle produced 2,000
distinct inputs and matched all 256 official byte-aligned short-message vectors.
These are mathematical expectations, not captured target outputs. Primary
specification/vector identities and search accounting are retained in
[PRIMARY-SOURCES.json](PRIMARY-SOURCES.json).

From the repository root, with the authenticated capture materialized:

```sh
P=research/work-items/RE-013-visor-keccak-value-closure
PYTHONDONTWRITEBYTECODE=1 python3 -B "$P/collect.py" --out /tmp/keccak-native-fresh
PYTHONDONTWRITEBYTECODE=1 python3 -B "$P/corpus.py" --out /tmp/keccak-corpus-fresh
PYTHONDONTWRITEBYTECODE=1 python3 -B "$P/verify.py" --out /tmp/keccak-check-fresh.json
```

Every destination must be absent. The collector defaults to GNU Homebrew
objdump/readelf and `/usr/bin/objdump` LLVM; explicit tool options are available.
The verifier starts two clean native/corpus trees with different hash seeds and
time zones and compares stored bytes exactly. `-O` removes no checks because
requirements use explicit exceptions. New-client absence is intentionally a
pre-code chronology gate; a later implementation must provide a separate
post-source replay entry point rather than rewriting this frozen verifier.

Binding corruptions deliberately bypass whole-image/body hashes and test
selected operands, branches, call/data displacements, RELA and unwind records.
They are **binding checks**, not execution of a corrupted machine or automatic
semantic coverage. Ten separate mathematical wrong-rule witnesses exercise
padding, domain, rounds, rho/pi and byte order. Neither category is a compiled
source-mutant result. Complete raw decoder exports are gzip data, never code to
execute. Runtime caches are excluded from the final manifest.

Ownership was checked against the saved full PR bodies/path sets through 1611.
Adjacent external PR1607 owns a different file-read envelope; no UTF-8/open/
read/probe/close claim or dependency is imported. Existing provider and capture
remain one project lineage; specification authors, tools, and peer review do
not create an independent target-source provenance claim.
