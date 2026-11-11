# Reference and generator execution boundary

Manual files were sealed before reference/generator authorship. The parent has
actually qualified `reference_math.py` against all40 literal manual cases:
`manual-qualification-01/result/RESULT.json` SHA-256
`777f00994e2a85ef285c34341203d2e42d2b24a8bd505df65060f17fc8342291`,
exit0, zero mismatches and empty stderr. This author did not rerun it.

Current source pins:

* `reference_math.py`: `3bc9d4e1474b475b0a1b8911cabe59c60d85fa64de5c8dfe7c86ffe3d82c079b`
* `qualify_manual.py`: `3f4aa45ffbaf9c1ae86ba459c374098480750993a51fde8fbf5a45326b01f997`
* `generate_corpus.py`: `9b5b36c485d542180cf3e5cbec7a9863d6f31d94952734a030ff01851a8483f8`

The generator is still **unexecuted** at this draft. Suggested parent-reviewed
commands, with cwd equal to this private `reference` directory, are:

```sh
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
  /opt/homebrew/bin/python3 -B -S generate_corpus.py \
  --manual manual \
  --qualification manual-qualification-01/result/RESULT.json \
  --output corpus-run-01

/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C \
  /opt/homebrew/bin/python3 -B -S generate_corpus.py \
  --manual manual \
  --qualification manual-qualification-01/result/RESULT.json \
  --output corpus-run-02
```

These commands are proposals, not authorization or claimed runs. Root records
the exact installed interpreter version/hash, source identities, clean env,
cwd, arguments, stdout/stderr and actual exit status for each admitted run.
The existing interpreter is used; no install or dependency resolution occurs.

Reads are limited to the generator's own bytes, its sibling reference source,
the explicitly supplied manual directory's pinned freeze/four files, the pinned
manual qualification result, and ordinary installed Python stdlib/runtime
initialization. Importing stdlib `random` may initialize its unused global PRNG
from operating-system entropy. The generator uses a separate Random instance
with the explicit fixed seed, so output does not depend on that unused global
state. This is not a claim that interpreter startup has no ambient reads.
The reference is compiled from the exact authenticated byte buffer into a fresh
ModuleType; no cached project bytecode loader or project-model import is used.
The pure reference itself has no imports or I/O. Hash checks precede its load.

Writes are limited to the eight documented files in the fresh requested output
directory, plus a compact JSON status on stdout. Existing output paths are
refused before reference loading; no retries, cleanup, file replacement, native
access, subprocess, network, environment lookup, Rust access, service, target
execution, instruction evaluator or emulator exists in these sources. The
generator does not alter original manual/source/qualification bytes.

Failures propagate as nonzero process exits. They are preserved in the parent's
raw command records and must be diagnosed; neither expected values nor limits
may be silently revised to manufacture a pass. Determinism and resource bounds
require actual two-run verification. This plan does not claim process isolation
by filesystem sandbox, native runtime equivalence, full protocol reconstruction,
Linux execution, allocation-failure testing or complete-iteration observability.
