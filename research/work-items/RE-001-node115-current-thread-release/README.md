# RE-001: node115 current-thread final-release helper

Component: foundation, a shared runtime dependency of TLS cleanup. Target:
Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates are ELF link-time
virtual addresses; upper bounds are exclusive.

## Question and new result

Own merged PR2434 left the helper behind the final FS:-0x428 reference release
opaque. This packet binds its complete FDE `0x5c98b40..0x5c98b89`: **73 new
bytes / 27 instructions**. The complete 288-byte / 50-instruction drain caller
from PR2434 is context, giving 361 exported bytes / 77 instructions in total.
No reconstructed-Rust byte comparison or full-scope gate progress is requested.

After the caller observes its TLS word unsigned >=3, it writes sentinel 2,
saves old_pointer-16 in a stack word, and atomically decrements the qword at
old_pointer-16. Only a zero result passes the address of that saved word through
slot `0x64dfe58`, uniquely relocated to this helper. The helper therefore reads
an allocation base from its input; it does not receive the old TLS pointer
directly. This is existing caller context, not a newly claimed caller body.

The helper's visible path, conditional on valid memory and returning callees:

1. Read allocation base A from the input word, and buffer pointer P from A+24.
2. If P is non-null, load N from A+32 and write **one zero byte at P**. This
   write precedes the length test and also occurs when N is zero.
3. Only when P and N are both nonzero, call slot `0x64df4a0` with RDI=P,
   RSI=N and EDX=0. Its unique RELATIVE binding is `0x635de30`, the shared
   deallocator already owned by peer PR2365. Its internals are boundary-only
   context here; EDX=0 is not independently promoted to an allocator ABI proof.
4. The subsequent A==-1 branch skips the remaining-count operation. This test occurs
   **after** the optional-buffer accesses: it is not an invalid-pointer guard
   for the whole helper and must not be moved to its entry in a reconstruction.
5. Otherwise, atomically decrement the qword at A+8. A nonzero result returns.
   A zero result restores the frame and tail-transfers A through `0x64e20d8`.
   The actual dynamic relocation is GLOB_DAT symbol 59, named `free` in this
   ELF's `.dynsym`/`.dynstr`. The payload deallocator and final free are distinct
   dispatch routes. Runtime interposition, successful deallocation and the
   lifetime of other references are not established by static bindings.

The primary FDE uses a zR CIE without an LSDA or personality field. The packet
binds the complete raw FDE/CIE records; it does not invent a local cleanup or
interpret the caller's action/type tables. Each body's full instruction stream
is checked independently against retained GNU and LLVM captures and Capstone.
LLVM's two standalone LOCK prefixes are joined only at `0x5c98b6c` and
`0x5ca54f3`, with exact continuation bytes. No normalization masks are used.

## Attribution and limits

Official Rust revision `59807616e1fa2540724bfbac14d7976d7e4a3860` is already
captured provenance context. Its `thread/current.rs` resets CURRENT to 2 before
dropping a recovered Thread; `thread/thread.rs` describes a pinned Arc using
the System allocator and an optional name backed by CString; the key guard
runs thread cleanup after TLS destructors. These sources support the
current-thread / strong-and-weak-reference / optional-name interpretation.
They do not prove the original symbol, exact field ABI, local patches, complete
object size, compiler flags or source-built equivalence. Only observed offsets
and dispatch routes above are established here. Source URLs and the hashes of
the exact reference text read are in `references.json`; upstream text is not
copied into this packet. No claim is made that clearing one byte wipes a name.

The 73-byte helper is new scope. The 288-byte caller is own merged2434 context;
the shared deallocator is peer2365 context. Existing worker-completion evidence
contains calls to this helper but does not retain its body. The 308-record
standard-library census was numerically checked for intersecting extents and
contains none. Existing build-selection and entry-checkpoint hits refer to
neighbouring bodies or file offsets; the database-root packet already binds
the same free import in another path. Indexed searches are not proof of
exhaustive non-overlap; final live ownership checks are recorded separately.

The existing TLS collector leaves this helper boundary opaque; it cannot bind
its body, import writer or final count/free edges. The task-specific collector
adds that missing evidence path and controls, using existing readers rather
than changing shared tooling. The collector reuses the author's MIT TLS ELF/FDE/native-reader module from
merged2434, pinning its exact SHA-256 before importing it. It does not modify
shared tooling or imported evidence. No captured code is executed or emulated,
no allocator or scheduler is mocked into a claimed native result, and no Rust
implementation, network, chain, deployment or full-runtime claim is made.

## Reproduce

With the pinned input materialized and installed Capstone 5.0.7:

```sh
python3 -B research/work-items/RE-001-node115-current-thread-release/collect.py --check
python3 -B -m unittest discover -s tests -p test_node115_current_thread_release.py -v
python3 -O -B -m unittest discover -s tests -p test_node115_current_thread_release.py -v
python3 -B research/work-items/RE-001-node115-current-thread-release/export.py --output work/current-thread-recapture
make doctor verify test catalogue-check reproduce
```

The focused suite checks genuine static inputs and corruption below both body
hash and instruction-byte shortcuts: operands/branches, physical relocation
writers, the import-name bytes, raw unwind records, missing/duplicate FDEs,
non-executable section membership, altered native captures, LOCK continuation
and relabelling context as new. These are comparator controls, not runtime tests.
All 10 focused tests passed normally and under optimized Python with Capstone
5.0.7, and normally with Capstone 5.0.6. A second export under seed 91 and
Asia/Seoul matched all seven native/specification/record files byte-for-byte.
## Repository validation

The clean required run on 2026-11-04 passed `make verify`, all 584 files in
`make test` (0 failed), `make catalogue-check`, and `make reproduce`. Exact
commands, runtimes and SHA-256 hashes of the captured logs are in
`validation.json`. The earlier run's two environment-only permission failures
and the seven-test permission recovery remain preserved there and in the
bootstrap diagnostic record; the pinned input bytes did not change.

`make doctor` was also run on the isolated host and returned 2. It reports that
`rg` and `git-lfs` are unavailable and that the repository has no complete
Cargo manifests/locks, exact target build flags/compiler provenance, or
accepted full reconstruction/comparison harness. This packet uses the
available static analysis tools and verified retained bytes; it does not claim
whole-node build readiness or an accepted node implementation. The original
preparation run's stale-catalogue result is preserved as a separate negative
result; regeneration adds this work item to the generated README/SVG inventory
without changing any gate.

Remaining unknowns include object construction and all other ownership paths,
the shared allocator's runtime contract, complete source/build identity and
thread-exit ordering under actual libc interposition. All 92 gates remain
unchanged. The static checks are complete. The final pre-submission review confirmed the pinned upstream base (05bc2de303c05525b71e7e257426e741bc66a390), current ownership and fork, no open claim on 0x5c98b40, and no overlap with the latest node115 teardown PR. All files in the 16-path publication allowlist matched their SHA-256 values before this commit.
