# Independent carrier evidence

This supplement preserves a separate Python GNU/BSD ar-format parser and
pyelftools 0.32 ELF check. It does not invoke an installed GNU `ar` tool. Its
object/comment reading is independent of `scan_object_provenance.py`.

`parser-agreement.json` compacts the actual earlier independent run into all
110 exact RC2-carrier identities: member names, indexes, payload offsets,
sizes and SHA-256 values in the four compiler/profiler libraries. Those
identities were also compared to the final canonical member inventories
without rereading the archives. The receipt retains archive/library hashes,
original method/output hashes, counts and the original run's qualification.

`independent-popcount-1.94.1.asm` and `independent-popcount-1.95.0.asm` are
unchanged native outputs from the two actual member disassemblies.
`reader-identities.json` binds them to their distinct member/library/archive
hashes, tool binary SHA-256, version, exact options and dependency assessment.
`objdump-version.txt` is the exact version output. The original installed
reader was Xcode's `XcodeDefault.xctoolchain/usr/bin/llvm-objdump`, Apple LLVM
21.0.0. All paths here are portable or distribution-relative; no user home
path is needed.

The two code bodies and listings are identical, but the complete object
members and producer stamps differ. The evidence does not select a unique
historical release or carrier. The final `ret` consumes the caller's return
address. No whole-object/unwind closure, runtime behavior, target function
boundary or complete xref census is claimed. Sanitizer/runtime carriers are
outside this supplement. The main probe owns the three target comparisons.

## Reproduce the supplementary check

Use Python 3.10+ in an environment that already has **pyelftools 0.32**. The
script checks that dependency; it never installs tools or dependencies.
First acquire/authenticate the two archive inputs and run the primary probe
using the parent packet's commands. Then, from the repository root:

```sh
packet=research/work-items/RE-002-std-clang-carriers
python3 -B "$packet/independent/check_carriers.py" --repo . \
  --inputs work/re002-std-inputs --primary work/re002-std-results \
  --out work/re002-independent --native-objdump /path/to/llvm-objdump
```

Choose a fresh output directory below `work/`. The explicitly selected native
reader must already exist and support ELF input on stdin with the recorded
LLVM options. Without `--native-objdump`, the script still compares all
carrier identities and verifies both popcount symbol extents, bytes and
relocations, but emits no newly decoded listings. The observed native tool
was macOS Apple LLVM; other native tools/platforms are not claimed tested.

The adaptation reads only the two named libraries per archive, using the
separate Python ar-format parser and pyelftools for ELF comments/symbols and
relocations. Tar iteration/decompression still traverses archive records.
It checks pinned archive hashes from the parent `inputs.json`, never follows
nonregular tar members, never extracts files and never executes members. It
compares exact carrier identities against `members-<version>.jsonl` from the
primary probe. A mismatch aborts; matching records do not authenticate the
primary parser independently of the signed archive.

`adaptation-validation.json` states the checks actually observed during
packaging: AST/synthetic controls, retained-record comparisons and both raw
listing validations. At initial packaging the adapted archive entrypoint had
**not** been freshly run. The older run and newly packaged method are not
represented as the same execution. A later qualified run needs its own
receipt. `files.sha256.json` lists the packaged file hashes.

The packaged entrypoint was subsequently run on the authenticated archives with
Python 3.12.14, existing pyelftools 0.32 and Apple LLVM 21.0.0 under IP-denied
analysis. `qualified-run.json` records exit 0, four libraries, all 110 exact
carrier comparisons, both native listings and the raw result digest. Both fresh
listings are byte-identical to the retained listings. An initial attempt with
the repository-check interpreter lacked the optional pyelftools dependency and
failed before creating output; the qualified run used an existing environment,
without installing anything.
