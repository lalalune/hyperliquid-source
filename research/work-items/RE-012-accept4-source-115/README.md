# RE-012: node115 accept4 source and caller boundary

This packet resolves the complete node115 accept helper's raw address/error
contract and its four actual caller integration boundaries. The target is
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `8fd8db680ec4bfef40996e5616bce3d5156d0b86` keeps node115 as the exclusive
active target and retires the old task tree. No captured code, emulator,
socket or live service is executed.

The full helper is `[0x475b050,0x475b154)`, 260 bytes / 64 instructions. Fresh
FDE/CFG/import evidence establishes its accept4 arguments, whole-u16 family
selection, IPv4/IPv6 address conversion, raw output layout, full output-pointer
return, packed errno and close ordering. Inactive IPv4 bytes16..35 come from
unspecified post-import registers; they are not assumed zero or preserved.
Unknown family publishes its error before requesting close.
[PROOF.md](PROOF.md) derives every branch and its normal-return premises from
the complete [static record](static/records.json).

The node115 census has four callers, rather than historical node94's five.
Three reject IPv6 after registration; the fourth forwards both address
variants. Error-close arguments are reloaded after opaque callbacks. The
supporting error classifier is now192 bytes and clamps simple-tag values to42;
the helper's fixed20 still reaches the ordinary error handoff. Six full FDEs
total18,430 bytes /3,671 instructions: 260 primary bytes plus18,170 context
bytes. Five tables (552 bytes), three nine-byte rejection strings and three
unique GLOB_DAT import slots are also bound. Full caller bodies are context;
registration, cleanup, readiness progress and whole async behavior remain open.

## Historical input and licensed source

Historical research served as a hypothesis, with new node115 extraction for
every address, FDE, caller, import and table. The
[migration record](migration-boundary.json) finds only three changed call
displacement fields in the two complete captured helper bodies. It masks12
operand bytes, with248 unchanged bytes and nine actual byte differences. This
is a cross-release observation, not source-build or component acceptance credit.
The differing caller count and classifier prevent whole-caller transfer.

The published [Mio1.0.2 source](https://github.com/tokio-rs/mio/blob/v1.0.2/src/sys/unix/tcp.rs)
and [address conversion](https://github.com/tokio-rs/mio/blob/v1.0.2/src/sys/unix/net.rs)
provide a licensed candidate. We reauthenticate both original/repeat Linux
objects from the merged listener source packet, including its exact compiler,
build commands, source archives and licenses in
[source-provenance.json](source-provenance.json). This is not a new build or
independent replication. Required source/build records now reside in
`licensed-build-inputs.json.gz`, alongside the two complete official crate
archives; all308 source files match the original source manifest. Historical
path strings are archive labels, not live file dependencies. No retired task
tree or node94 artifact is needed by this packet's replay. Its complete
`TcpListener::accept` FUNC and PC32 FDE
contain239 bytes /61 instructions, compared against the entire260-byte node115
helper. The [new target comparison](comparison/comparison.json) is unmatched,
without masks, trimming or padding. The candidate closes before publishing its
unknown-family error, unlike node115.

The target `.comment` labels rustc1.95.0 (`59807616e`, 2026-04-14), whereas
the retained candidate was compiled with rustc1.94.1. This observed label does
not authenticate the original toolchain or explain the mismatch by itself;
the candidate is explicitly a nonmatching diagnostic build. See
[dependency-leads.json](dependency-leads.json).

One `node115-mio-accept4` unequal-extent dependency candidate is registered in
`research/byte-windows.json`. [The audit](registration-audit.json) confirms
all previous aligned totals and comparisons are unchanged. No acceptance gate
advances. Crate/version identity, original compiler/build flags, Rust layout
equivalence, integrated source-built node and whole-ELF equivalence remain open.
The bounded package-version regex found no Mio version string in this capture;
source correspondence is not unique original-version attribution.

## Checks and replay

From the repository root with pinned artifacts and LFS objects materialized:

```sh
python3 -O research/work-items/RE-012-accept4-source-115/verify.py
LLVM_OBJDUMP=/usr/bin/objdump PATH=/opt/homebrew/opt/binutils/bin:$PATH \
  PYTHONPATH=tests python3 -m unittest -v test_accept4_source115
```

The verifier checks the closed regular-file/directory inventory, all manifest
hashes, fresh node115 static records, complete GNU/LLVM byte partitions, raw
archive, source/build pins, source FUNC/FDE/relocations and registered comparison.
Nineteen packet tests include60 target integrity controls, all65,536 family
values and six actual temporary-tree rejection controls. Four source-ELF and
four comparison controls exercise the retained candidate. Three additional
licensed-input controls reject an archive change, a source-file change below
the archive hash, and an introduced source symlink. The mathematical
relation is a reused proof aid revalidated against node115 bytes, not an
independent runtime oracle or production networking implementation. Synthetic
raw observations are not claims about valid kernel or public Rust values.

[validation.json](validation.json) and lossless raw logs report actual checks.
Full `make test` is required and will run on the final committed head; it is
pending at packet freeze. No full-suite or hosted-CI success is claimed here. The collector and comparator are bounded
analysis tools needed to retain/replay this task's new target evidence; shared
tooling and submodule pins are unchanged.

The retirement rebase exposed a real missing-import failure for the removed
`socket_calls_static` helper; its exact log is retained. Only the generic image,
FDE and relocation methods needed here were moved into the node115 collector.
Existing `elf_index` and `fde_extents` remain its shared dependencies. The
source archives replace deleted provenance-path reads, without restoring old
tasks. Fresh exports normalize the target filename to
`<authenticated-node115>`; instruction bytes are unchanged and fully checked.

[sources.jsonl](sources.jsonl), [claims.jsonl](claims.jsonl) and
[countersearch.json](countersearch.json) provide the insane-research handoff.
Both decoders and the relation share the captured artifact as their authority.
The Linux [accept](https://man7.org/linux/man-pages/man2/accept.2.html) and
[close](https://man7.org/linux/man-pages/man2/close.2.html) manuals support
interface names/conventions; actual predicates and order come from bytes.
New analysis code/docs are MIT; imported public source and object evidence
retain the upstream license notices in the hash-bound source packet.
