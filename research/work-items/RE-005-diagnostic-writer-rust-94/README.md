# RE-005: independently authored newline callback protocol

This is the implementation addendum to the existing conditional diagnostic
field/adapter proof, within the **same #1030 outcome**. Target: node #94,
91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Preserved parent: `03fe0523bd86a74435d0606e70c6018950b930b1`, tree
`ee1344639d4c36a38bceee58a86ea0f7fdf6bdb8`.

Before this addendum, #1030 established conditional static contracts but no
project-authored Rust implementation or actual Rust component build. The
[new no_std module](../../../src/node94-newline-writer-protocol/README.md)
implements only the qualified **byte-request / flag / low-result-byte protocol**
of adapter `[0x157d000,0x157d26e)`, 622 bytes / 176 retained native rows.
The parent `[0x1571f50,0x15720d6)`, 390 bytes / 109 rows, remains credited
supporting context and is not implemented. The inherited combined 1,012-byte /
285-row denominator is evidence inspected, not new machine-code matches.
All 19 original files, native exports and prior negative evidence remain exact;
[ORIGINAL-19-PRESERVED.json](ORIGINAL-19-PRESERVED.json) binds their actual public
Git blob identities. No original manifest inventory is widened or restamped.
New source was authored independently under MIT without copying the unlicensed
inferred reference or transplanting original machine code.

## Qualified protocol and implementation argument

Read the unchanged [native proof](../RE-005-diagnostic-field-trace-94/SCAN-AND-PRETTY-PROOF.md)
and [physical assumptions](../RE-005-diagnostic-field-trace-94/ASSUMPTIONS.md).
The native proof establishes the first-LF scan, strict progress, in-bounds
nonempty LF-inclusive chunks, optional nonempty final tail, exact four-space
requests, PRE-payload flag store and both nonzero-AL error cuts. It covers its
full adapter under those conditional immutable-input/normal-callback conditions.

The Rust module uses the standard byte-slice `split_inclusive` contract, with
LF as its predicate, rather than recreating the native two-word scan. For any
finite slice, its chunks end at each LF index plus one and, if nonempty, the
remaining final end. They partition the input, retain every byte, exclude an
empty input chunk and exclude a post-terminal-LF empty tail. Thus their cut
sequence equals the target-proved byte intervals without a UTF-8 assumption.

Induct over those chunks and normal callback returns:

1. At a chunk header, sample the current `Cell<u8>`, including any prior
   callback mutation. Any nonzero byte requests the exact four spaces.
2. Nonzero indentation callback byte returns 1 before this chunk's helper
   flag store or payload call. Its own Cell mutation persists. Zero permits
   continuation regardless of the Cell value the callback left.
3. Store whether the chunk's last byte is LF as 0/1 **before** calling its
   payload proxy. This overrides an indentation-success mutation, not a
   payload mutation. The recorded callback-entry flag exposes this ordering.
4. Nonzero payload byte returns 1 without another store. Zero advances to the
   next chunk; its current Cell is sampled afresh. Therefore arbitrary payload
   flag mutations persist on error and control next-chunk indentation on success.
5. With no next chunk, return 0 without extra requests. Terminal LF and a final
   no-LF payload that sets the Cell nonzero do not create another empty request.

There are at most twice as many outer proxy calls as nonempty chunks, and
strict chunk progress plus finite normal callbacks supplies termination in
this domain. The source contains no flag get/set or callback outside the loop;
the standard iterator's empty-input contract supplies no loop iteration.
Matching final Cell values alone is **not** a physical no-read/no-write trace.
The result is a newly chosen Rust `u8` low-byte projection; native higher RAX
bits are not inferred from failure AL=1.

The new interface requires valid Rust references even on empty input, stronger
than native raw empty-pointer states where the adapter need not access input,
B or a method. Callback panic/unwind, faults, concurrency and unsafe alias
corruption are excluded. Native frame/return/metadata/callee-save conditions
remain external. Cached post-prologue D/V/B arguments and fresh method-entry
loads must be represented by the supplied proxy if a bridge is asserted;
a stable closure object does not prove stable native method identity.
No original ABI, vtable, writer/formatter type, physical rendering, complete
parent, unwind/runtime equivalence, original compiler/byte identity or component
gate is claimed.

## Independent oracle and real component observations

The runner admits **one immutable in-memory node snapshot** by full digest.
Every ELF, literal, metadata, native operator/CFG certificate and oracle fact
comes from that exact object. Original parsers are unchanged. GNU receives
only their tiny copied raw spans, never an image pathname or full-image file.
The expectation generator separately enumerates LF indexes plus a nonempty
final end, then applies the target-derived abstract callback/flag relation to
specified normal-callback stimuli. It does not invoke Rust or use
`split_inclusive` to generate expected cuts.

The separately linked **production** library receives only input bytes,
initial flag and indexed callback return/mutation actions. Those actions are
an environment stimulus, not expected traces. The Rust test driver logs actual
request index/bytes/entry flag/supplied return/mutation and final status/Cell.
It does not attach expectation-derived indent/payload labels: a payload may
itself equal four spaces. Absent script entries use a normal default, making
terminating mutants' extra requests observable instead of harness panics.
This is input-only source/data-flow separation, not a filesystem sandbox.
The driver and unit fixture are excluded from the no_std production rlib.

Observed [RESULT.json](RESULT.json):

- **3,023 distinct stimuli** cover all one-byte values, arbitrary high bytes,
  NUL/CR, empty/leading/consecutive/trailing LF, all-space payloads, word/block
  boundaries, raw initial flags including all 256 values, callback mutations
  and nonzero return-byte error cutoffs.
- Both real unoptimized and optimized profiles run one ordinary Rust test
  over that corpus plus **3,023** separately linked production transcript
  comparisons. Every transcript matches the fresh native-contract expectation.
- Seven mutants actually compile. Nonzero-flag-as-one, three spaces, CR cuts,
  post-payload flag store, ignored indentation error, raw payload AL return
  and post-terminal-LF empty request yield respectively **1,931 / 2,296 /
  1,331 / 2,287 / 324 / 297 / 346** differing production transcripts. Each
  compiled ordinary unit program fails a semantic assertion with exit 101.
- Two optimized **9,440-byte** own rlibs are raw equal, without normalization,
  SHA-256 `11bbce643e51069eb120045cfba5e4fe64d98eb3442f112f2ec4a39288d728c2`.
  This is own-build reproducibility, not comparison with original node bytes.

All **49** actual subprocess records and **98** stdout/stderr byte streams
are retained in [RAW-LOGS.json](RAW-LOGS.json), with exact UTF-8 re-encoding,
length and hash; no normalization is applied. They include identity probes,
actual library/test builds, production executions, mutants and two rebuilds.
[BUILD-INPUT-AUDIT.json](BUILD-INPUT-AUDIT.json) records identical before/after
25 source/original-file identities, all 19 original public blobs, target bytes
and all 103 authenticated compiler-prefix payloads. [TOOLCHAIN.json](TOOLCHAIN.json)
identifies the existing verified research rustc 1.94.1 and explicit C driver;
this is not a recovered original node compiler. No Cargo workspace, dependency,
lockfile, original callback stub or fake full formatter is introduced.

The initial oracle setup failed because the unchanged byte parser calls
`bytes.index`, which mmap lacks. Its failure summary and resolution are
retained. Before any compiler run, the provisional view adapter was removed
in favour of the admitted immutable bytes snapshot. No original parser was
modified or failure restamped. Four focused oracle/admission tests pass both
normally and with `-O`; Python checks do not substitute for the real Rust run.

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/owned-short python3 -B \
  tools/bincode_diagnostic_writer_rust.py --rustc /path/to/verified/1.94.1/rustc \
  --output /tmp/diagnostic-writer-build-new --controls
python3 -B -m unittest discover -s tests -p test_bincode_diagnostic_writer_rust.py -v
```

Use fresh physical output directories. Captured node/visor code is never
executed or emulated. Finite compiled transcripts corroborate the general
source/protocol argument; they are not a formal compiler proof. Independent
review, exact-commit repository checks and actual hosted status are reported
separately in the same PR after the frozen source is qualified.
