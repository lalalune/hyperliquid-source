# RE-012: Node115 CLI output record and owned-value boundary

- Component: `node-runtime`; related `serialization` and startup integration.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: What does the complete output constructor at
  `0x564d390..0x564d6d8` write, in what lookup order, and how is its optional
  owned value handled before the two run-command results are tagged?
- Status: new target-bound observations plus qualified layout interpretation.
  No component gate, first-party byte credit or implementation claim.

The current CLI packet in [PR2034](https://github.com/lalalune/hyperliquid-source/pull/2034)
explicitly excludes this helper's internal behavior. Its immutable reference
head is `d675d68d872ed8402c21845b610ca2abd619e4bf`. That packet's command,
lookup, configuration and parser claims are credited as boundaries, not
re-submitted. Their current ELF bytes are independently exported here only to
bind the selected dependency/caller edges. Historical Node94 output work is
migration context, not evidence for this release; the new constructor has an
owned optional value and a different size, not just different addresses.

## New result

The 840-byte/200-instruction constructor queries twelve presence values and
copies their returned low bytes to output offsets `24..35`. It also reads
`write-user-clearinghouse-states` as an optional **value**, not a Boolean:
absent uses the observed MIN64 sentinel, present-empty uses `(0,1,0)`, and
present-nonempty allocates and copies the returned byte view. Its three words
occupy offsets `0,8,16`. The absent pointer word is inactive scratch, **not an
invented zero**. The exact string's later meaning is not established here.

A required `replica-cmds-style` lookup admits exact case-sensitive bytes
`actions=0`, `actions-and-responses=1`, `recent-actions=2`; overlapping immediate
and SIMD comparisons cover all bytes. The tag is stored at offset36. The
observed write span is37 bytes; this does not establish a37-byte Rust type,
object alignment, padding, ownership API or stable ABI.

Full instruction/export evidence and the selected writes are in records.json;
CONTRACT.md spells out premises and failure/unwind boundaries. The two selected
calls at `0x56550de` and `0x56551e9` pass the destination+8 and are followed by
command qwords2/3. Slot `0x64ebcb8` has its own RELATIVE relocation to this
constructor. No effect on files, sockets, services, ledger or networking is
inferred merely from option names.

## Evidence denominator and scope

All coordinates are linked ELF VAs before load bias. File offsets, actual
FDE/CIE bytes, complete Capstone instruction records and original GNU exports
are retained. GNU and Capstone instruction **addresses and bytes** agree for
all4 complete selected FDEs:5,996 bytes/1,417 instruction rows. Of those,
**only840 bytes/200 rows are the new primary constructor**. The other5,156
bytes/1,217 rows are pre-existing lookup/command context, not new function
ownership, reconstructed implementation coverage or a whole-CLI denominator.
There are no operand masks, transplanted bytes, target interpretation/execution
or generated source equivalence claims.

The primary LSDA supplies three call-site intervals; its local cleanup landing
is pinned. Dynamic import names/RELATIVE targets, all primary calls/jumps,
lookup literal addresses/lengths, raw style chunks and two actual caller sites
are retained. Hashing/table construction, general UTF-8/value conversion,
allocator/error internals, arbitrary helper side effects, exception action
chains and parser/default construction remain explicit boundaries.

## Reproduce

Python3.12, Capstone and GNU objdump are analysis tools only; the node is never
run. The operator used native Windows Python3.12.1 and GNU objdump2.47.
The installed Capstone distribution metadata says5.0.9; its actual API reports
binding5.0.7/core(5,0,1280), which is what records.json preserves. Do not relabel
those observations. Use a supported installed binding/library explicitly; no
package install or global configuration is performed by these scripts.

From the repository root with the authenticated LFS artifact materialized:

```sh
python -B tools/node115_cli_output_config.py --out work/cli-output-new
python -B -m unittest discover -s tests -p test_node115_cli_output_config.py -v
python -B research/work-items/RE-012-node115-cli-output-config/verify.py
make doctor
make verify test catalogue-check
make reproduce
```

`--objdump /absolute/path/to/objdump` selects an installed GNU tool. Generation
requires an initially empty output directory and uses only explicit objdump
subprocesses with finite deadlines. Temporary/native exports stay under the
selected work/output directories. No target, shell, provider or network service
is launched. Keep full/reduced provider profiles distinct.

The packet verifier rederives the target-bound JSON, checks its closed file
inventory and manifest, verifies retained GNU bytes against the recorded
instruction walk, and makes a fresh GNU/Capstone address/byte comparison. Raw
GNU stdout remains original; textual presentation may differ across platforms,
and is not silently normalized or asserted raw-identical on another provider.

## Validation and remaining work

See validation.json for exact local outcomes and original failure boundaries.
The initial base `make doctor` passed, while `make verify` failed importing the
public signing key with GPG(exit2) after all6 artifact SHA checks passed.
That is a failed signature gate, not a verified signature or a suite pass.
The original collector's unsupported omitted-LSDA-table failure and a test
negative-control byte-coordinate transcription error are preserved in operator
logs, with their concrete corrections; no assertion was removed.

Ten target-grounded controls include56 actual style-comparison byte mutations,
five destination-displacement mutations, name/callee, FDE-end, LSDA and RELA
changes. Integrity rejection is distinguished from changed semantic
observations; they do not execute or emulate the captured node.

Rust implementation/build/lockfile, original public API, native input/output
execution, whole dependency closure and whole-node equivalence are **not yet
implemented or measured**. All92 acceptance gates remain unchanged. The next
question is the command factory/default source and how the optional value is
consumed by actual run-mode initialization; do not infer that downstream
behavior from this constructor's option spelling.
