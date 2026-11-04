# RE-012: node115 BLST lazy-pool construction and failure propagation

Component allocation: node-runtime / foundation, with public BLST, threadpool
and Rust runtime dependencies. Target: node115 Linux x86-64,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The CPU getter's actual callers lead to a BLST lazy shared pool. This packet
closes the construction boundary: once callbacks select a count, distinguish
zero rejection from the generic builder's zero-iteration path, make per-worker
spawn calls, detach successful handles, and publish the global wrapper only
after construction and allocation succeed. A pthread-create error is encoded
by the lower boundary, becomes the wrapper's zero-word error representation,
and reaches an unwrap failure rather than a recoverable constructor result.
This does not identify an eager node-startup executor.

[CONTRACT.md](CONTRACT.md) gives the argument/store order, domain qualifications,
count-loop proof, actual import edges and unresolved boundaries. Five primary
complete FDEs contain 2,046 bytes; five context FDEs bring retained evidence to
13,711 bytes / 2,932 instructions. Twenty full GNU/LLVM exports agree with
Capstone at every instruction boundary after 62 explicitly enumerated LLVM
LOCK-prefix display joins. No bytes are removed or masked. The original strict
boundary failure is retained, along with its unmodified collector source hash.

The actual diagnostic relocations identify vendored BLST and threadpool paths.
Official BLST 0.3.15/0.3.16 and threadpool 1.8.0/1.8.1 selected source functions
are equal, so these findings do not identify exact original revisions. Full
licensed sources, notices, pins and counterchecks are retained in
[sources.json](sources.json), [source-comparison.json](source-comparison.json)
and `source-archive.json.gz`. Each function slice ends at its closing brace,
excluding the final LF; the complete source files retain their original bytes.

## Reproduce

From the repository root, with installed Capstone 5.0.7 and the authenticated
artifact materialized:

```sh
PATH=/opt/homebrew/opt/binutils/bin:$PATH LLVM_OBJDUMP=/usr/bin/objdump \
  python3 -B tools/node115_blst_threadpool.py --check
python3 -B -O research/work-items/RE-012-blst-threadpool-115/verify.py
python3 -B -m unittest discover -s tests -p test_node115_blst_threadpool.py -v
```

A fresh native-disassembler export is optional and does not execute the node:

```sh
PATH=/opt/homebrew/opt/binutils/bin:$PATH LLVM_OBJDUMP=/usr/bin/objdump \
  python3 -B tools/node115_blst_threadpool.py --check --output work/blst-threadpool115-replay
```

`commands.json` and `validation.json` record actual checks, tool versions,
failures and their recovery. `validation/raw-streams.json.gz` binds retained
output bytes to their labels and hashes. The packet verifier rejects unknown
files/directories, duplicate/missing manifest rows, symlinks (including parent
components), damaged source archives and altered target evidence.

Full `make test` on fixed head `ab5a9b9d062b55db897f6cffabe2759735c123a0`
passed: 77 files, 394 reported tests and 3 skips. The runner recorded every
test-file hash and confirmed that all qualified sources stayed unchanged.
The independent review of that same head found no semantic blocker; its exact
36-file bundle, including the reviewer's initial LF-boundary failure and
correction, is retained as `peer/portable-review.json.gz` inside the raw archive
(SHA-256 `af19108eb7614183b74f496b9de301ad26f6c2afe933893b264563dcb0581a02`).
These are local results; no hosted-CI success is claimed.

The new task-specific collector is needed because existing generic ELF/FDE
helpers do not establish this construction's byte-bound call/argument/store,
loader-data or failure relations. It reuses those helpers and previously
owned static-export code; no shared analysis framework or target pins change.
Target corruption controls run below the full-file digest check and challenge
instruction anchors, complete bodies/extents, relocation writers, literals,
source descriptors and zero-fill classification. Temporary-tree controls
challenge evidence admission separately; neither set is target execution.

No Rust runtime component, source build, compiled-code match or native
behavior corpus is claimed. Padding/inactive payload bytes are unspecified;
workers, scheduler, Once, mutex/poison internals, allocation/cleanup helpers,
full unwind actions and cryptographic consumers remain open. No progress gate
is advanced. The next unresolved boundary is worker/job execution and its
actual synchronization contract, outside this packet.

New analysis code/docs: repository MIT. Upstream licenses are preserved.
Attribution: OpenAI / gpt-6-astra / Codex 0.166.0; independent authoring and
static analysis, no private inferred source copied.
