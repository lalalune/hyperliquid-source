# RE-012: permanent worker completion and conditional exit, node #115

This packet connects the private `thread_spawn_forever` and `tokio_spawn_forever`
completion paths to their oneshot sender, actual receiver task, delay request and
imported `exit(1)` edge. A diagnostic saying “crashing” is insufficient evidence:
the exit is conditional on scheduling, successful helper returns and a ready
delay. Both a received message and a closed receiver take that later path.

Component: `node-runtime`. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Coordinates are linked ELF VAs.
The [contract](CONTRACT.md) separates observations, conditional interpretation,
valid ownership/state premises and unresolved runtime behavior.

The twelve primary complete FDEs cover 8,821 bytes. With fifteen complete caller,
receiver-dispatch and delay context bodies, the exported evidence covers 27 FDEs,
17,695 bytes and 3,974 instructions. GNU and LLVM decode every exported byte;
Capstone independently checks instruction boundaries. The collector authenticates
106 selected relocation writers, 35 source-location records, six jump tables,
60 instruction anchors and 255 LSDA call-site rows. No target byte is masked.
LLVM's 69 enumerated LOCK-prefix display joins are exact address/byte checks.

The analysis blocker was that existing ELF helpers could locate sections and FDEs,
but no checker bound this private completion family to its concrete callback,
oneshot state transitions and exit import. The new task-specific collector uses
those existing helpers and adds only this digest-bound evidence/check path.

The [machine-readable observations](static/records.json) and
[byte specification](spec.json) bind the complete bodies and actual data edges.
Each body has `.gnu.txt` and `.llvm.txt` exports in `static/`.
[Commands](commands.json), [validation](validation.json),
[claims](claims.json) and [countersearch](countersearch.json) retain the scope
and before/after qualification. The lossless base64 raw archive preserves the
initial strict decoder failure and initial over-specific rejection-message test
failures as well as their corrected checks. Command paths refer to research
checkouts; no private runtime state, keys or user fixtures were used.

Public MIT-licensed Tokio sources are interpretation evidence only. Two official
commits are pinned in [sources.json](sources.json), with complete selected source
files and licenses in `source-archive.json.gz`. Three sender/completion slices
are identical across those releases; the receiver slice retains a cooperative
poll module-path change. [The raw source countercheck](source-comparison.json)
does not identify the original vendored version, local patches or compiler.
The private `base/src/lu.rs` implementation was neither available nor copied.

Reproduce from the repository root with Python 3.14.3, Capstone 5.0.7,
GNU objdump 2.47.20260726 and Apple LLVM objdump 17:

```sh
PATH=/opt/homebrew/opt/binutils/bin:$PATH LLVM_OBJDUMP=/usr/bin/objdump \
  python3 -B tools/node115_worker_completion.py --output work/worker-completion-replay --check
python3 -B -O research/work-items/RE-012-worker-completion-115/verify.py
python3 -B -O -m unittest discover -s tests -p test_node115_worker_completion.py -v
make doctor verify catalogue-check reproduce
make test
```

The first command disassembles the authenticated file; it never executes it.
The packet verifier needs the retained exports, not installed native decoders.
It rejects unlisted files/directories, symlinks in any checked path component,
duplicate/escaping manifest rows and altered evidence. Tests exercise real
instruction/FDE/data/relocation/import-name corruptions under optimized Python.
Independent review used its own ELF/RELA/LSDA parsing and fresh GNU/readelf,
checked all 27 bodies and the source countercheck, and found no blocker in this
bounded contract. Its exact 128-member portable bundle is retained as
`qualification/peer/portable-review.json.gz` within the raw archive (SHA-256
`4c91685288e17a07e05f3284bae43f53f407badce994260b7ca6ca5230d5db54`).
The exact focused/global/full-suite outcomes are in `validation.json`; pending
checks are not represented as passes.

This is a static lifecycle reconstruction, not a Rust implementation claim or a
native behavioral fixture qualification. A fake scheduler or hand-written model
of only the flag masks would not close the remaining dependencies. No source
build or compiled-code comparison was performed, so no comparison window or byte
credit is registered. All full-node/component acceptance gates remain unchanged.
The next unresolved question is the scheduler/timer/cleanup progress contract;
it is outside this packet and no additional work is claimed here.

Attribution: independently authored collector, tests and analysis by OpenAI
`gpt-6-astra`, Codex 0.166.0, using the installed insane-research workflow. New
code/docs are MIT; upstream source retains its included MIT notice.

The full `make test` run on implementation commit `522ae812512b1d91c1c8d6ae1e2bf3fc59cf0e03`
passed 77 files, 395 reported tests and 3 skips in 1050.997 seconds.
All test files and the five qualified source/evidence files retained their hashes.
The final follow-up changes only evidence metadata; hosted CI is not claimed.
