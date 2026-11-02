# Node115 root CLI and configuration construction

This RE-012 packet maps the current target's root `chain`/`key` options,
validator ownership, fourteen selected-command branches and the 152-byte
configuration handoff. It resolves a material migration hazard: node115's
profile node-IP, unjailed and signer fields occupy different offsets from
node94. Node115 also embeds an unversioned `z_vendor/clap` source path, so the
old `clap-2.34.0` path is not a version pin for this target.

Target: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are linked ELF virtual addresses. The five primary FDEs contain
7,762 bytes; thirteen supporting FDEs bring the authenticated total to 23,003
bytes / 4,553 instructions. Context bytes are not implementation coverage.

| Primary body | Complete interval | Bytes |
| --- | --- | ---: |
| Root builder | `0x564d700..0x564df8c` | 2,188 |
| Chain validator | `0x564df90..0x564e0e9` | 345 |
| Key validator | `0x564e0f0..0x564e19b` | 171 |
| Configuration extractor | `0x564cce0..0x564cf36` | 598 |
| Selected-command extractor | `0x5654bf0..0x5655d5c` | 4,460 |

[CONTRACT.md](CONTRACT.md) distinguishes direct byte observations, licensed
source correspondence and unresolved behavior. [migration.json](migration.json)
contains independently authenticated old/new body identities, changed layout
and explicit non-transfer of node94 credit. [records.json](records.json) holds
complete instruction rows, FDE/CIE bytes, bounded LSDA call-site tables, all
selected call/jump/RIP references, 61,001 scanned RELA records' selected
bindings, source Locations, command comparison chunks and ordered output stores.
GNU/LLVM raw exports remain next to the record. The only disassembly display
normalization joins LLVM's split `LOCK` prefix at `0x2ae5dcb` and `0x2ae5ddc`;
no byte or operand is masked. The initial strict mismatch remains archived.

```sh
PATH=/opt/homebrew/opt/binutils/bin:$PATH LLVM_OBJDUMP=/usr/bin/objdump \
  python3 -B research/work-items/RE-012-cli-config-115/verify.py \
  --native-output work/cli115-replay
python3 -B -m unittest discover -s tests -p test_node115_cli_config.py -v
```

GNU `objdump`, LLVM `objdump`, Capstone and Python are static analysis tools
here. Neither the captured binary nor an instruction emulator was run. No
Rust implementation, behavioral corpus, original source build, byte-equivalence
or full CLI grammar claim is made. The 25,353-byte command factory, parser,
840-byte output-configuration helper and transitive allocations/conversions
remain boundaries. The complete larger caller is context, not a reconstructed
async/runtime state machine. No component gate or byte registry is changed.

[validation.json](validation.json), [commands.json](commands.json) and
[raw-streams.json.gz](raw-streams.json.gz) preserve actual checks and failures;
[verify.py](verify.py) rejects unlisted files, directories and symlinks, checks
all manifest bytes, re-derives target records and can repeat both disassemblers.
The small task-specific tool exists because historical tools fix node94
addresses/digest and cannot validate this node115 path. It adds no general
infrastructure or execution capability.

The packet was first qualified on `c3b77a8e` and rechecked on the node115-only
`8fd8db68` tree: 82 focused tests in both normal and optimized Python, 18 FDE
tests, exact GNU/LLVM replay and repository checks passed. The first
post-rebase catalogue check required regenerating the work-item inventory
from 28 to 29; its failure and successful recheck are retained. No retired
node94 tool, test or binary is needed for this packet's replay. A complete local `make test` run attempted all 77 files with zero failed files
(464 reported tests, 3 skips). Its invocation was `6a37eaad`; tool/test
sources remained unchanged through the peer documentation corrections.
The exact invocation inventory and raw results are archived. Skipped tests,
Linux runtime qualification and hosted CI are not claimed as passed.

Public Clap source is an interpretive comparison under its retained MIT
license, not first-party node source or an exact version identification.
[sources.json](sources.json) pins official URLs, revisions and hashes;
[upstream-source.json.gz](upstream-source.json.gz) retains the original public
bytes, including the 2.33.3 countercheck. Private source was not copied or
consulted. [research-handoff.json](research-handoff.json) records attribution,
claims, countersearch and limitations for integration.
