# spot-clearinghouse-inventory-94

Task ID: `spot-clearinghouse-inventory-94`, a bounded RE-001-style static inventory
within component `risk`, restricted to `l1/src/spot_clearinghouse/*`.
No progress gate is requested. The only changed paths are this new packet,
`tools/spot_clearinghouse_inventory.py` and
`tests/test_spot_clearinghouse_inventory.py`.

Target: node **#94**, `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
The binary was read and disassembled, never executed. No network, installation,
chain action, GitHub write, or reference/submodule modification was performed.
New analysis code and prose are MIT; captured bytes retain their upstream terms.

The bounded question is: which relocated Rust panic Location records name these
four source paths, which direct RIP LEAs reference them, which actual FDE extents
contain those instructions, and which diagnostic lengths, constant operands and
rel32 calls can be bound **within that set of extents**?

Read [RESULT.md](RESULT.md) for observations, unresolved probes, verdict, validation
results and non-claims. The result is an inventory of evidence, not recovered Rust.

## Reproduce

From the repository root, with Python 3 and GNU objdump already installed:

```sh
python3 tools/spot_clearinghouse_inventory.py --out research/work-items/spot-clearinghouse-inventory-94/
python3 -m unittest tests.test_spot_clearinghouse_inventory -v
python3 research/work-items/spot-clearinghouse-inventory-94/verify.py
python3 -O -B research/work-items/spot-clearinghouse-inventory-94/verify.py
make verify
make test
make catalogue-check
make reproduce
```

Observed environment: Linux x86-64, Python **3.13.5**, GNU objdump
**2.44** (`GNU Binutils for Debian`), Git **2.47.3**. Python uses only its standard
library and the repository's unchanged `elf_index.py` / `fde_extents.py`.
`make doctor` reports static analysis ready, exact rebuild not ready. No REA tool
is connected in this session; Ghidra/Java are unavailable. No provider was installed.

The generator checks the full input digest **before parsing or invoking objdump**.
There is no digest override. The optional `--binary` must still contain this exact
artifact. Both JSON outputs regenerate byte for byte, including under Python `-O`
and `PYTHONHASHSEED=0/97`. No absolute checkout path or timestamp enters the JSON.
The disassembly transcript includes the objdump version; a different provider
version can require review rather than being silently normalized.

The generator writes only `inventory.json` and `disassembly.json`; it never rewrites
the prose, verifier or manifest. After an intentional, reviewed packet edit, update
the manifest using exactly the verifier's five whitelisted members:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path
p = Path('research/work-items/spot-clearinghouse-inventory-94')
names = ('README.md', 'RESULT.md', 'disassembly.json', 'inventory.json', 'verify.py')
(p / 'MANIFEST.sha256').write_text(''.join(
    f'{hashlib.sha256((p / n).read_bytes()).hexdigest()}  {n}\n' for n in names))
PY
```

## Method and completeness

1. Verify the artifact SHA-256. Parse ELF64-LE x86-64 ET_DYN section mappings.
   Decode `.rela.dyn` R_X86_64_RELATIVE entries, preserving the raw relocation,
   pointer addend and file offset. Match pointers into `.rodata` whose paths start
   with `/home/ubuntu/hl/code_Mainnet/l1/src/spot_clearinghouse/`.
2. Decode each matching, aligned, 24-byte `.data.rel.ro` record as the relocated
   pointer, u64 byte length, u32 line and u32 column. Require a complete path ending
   in one of the four `.rs` basenames, nonzero line/column and a zero on-disk pointer
   before relocation. Malformed matching records stop the census. This is the
   observed Rust Location layout, not a guarantee about every compiler layout.
3. Decode **actual `.eh_frame` FDE and CIE records**, cross-checked against all
   121,299 `.eh_frame_hdr` entries. Reject start mismatches, duplicate starts,
   overlaps, zero ranges and section-crossing extents. Each published FDE includes
   its raw FDE/CIE bytes, indexed entry, exact extent and code digest. Adjacent
   unwind starts are never substituted for FDE lengths.
4. Search executable sections for the observed seven-byte `48/4c 8d` RIP LEA
   forms. These are candidates until a complete linear disassembly from the
   containing FDE start places the seven bytes on one instruction boundary.
   Require full instruction containment in the end-exclusive FDE interval.
   All 27 scoped candidates pass; none lacks an owning FDE.
5. Run installed objdump on temporary copies of **only the 30,475 authenticated
   scoped code bytes**. Commands use `-D -w -b binary -m i386:x86-64 -M intel
   --insn-width=16 --adjust-vma=<FDE-start> fde.bin`. The input is data, never run.
   Require contiguous decoding of the entire range, byte equality to the ELF,
   and no undecoded instructions. Preserve stdout, stderr, commands and status in
   `disassembly.json`. The `.data` label there describes the temporary raw input;
   the source ELF section is `.text`. This is linear decoding, **not CFG reachability**.
6. Probe the 12 distinct diagnostic strings in the scoped reference, using the
   first static fragment of each interpolated string. Also probe the user-suggested
   phrase `insufficient balance` and the generic runtime `Result::unwrap()` text
   observed in scoped code: **14 probes total**. Exact substring occurrence alone
   does not bind a diagnostic. Accept only a scoped LEA plus either the observed
   RDI pointer / ESI byte length / FF15 call setup, or the explicit u8-counted
   prefix immediately followed by `c0`. The latter is a description of bytes;
   formatter grammar and substituted arguments remain unresolved. Indirect-only
   literal references and instruction-built strings are not exhaustively searched.
7. For two selected binary64 reference leads, retain every `.rodata` occurrence
   and exact scoped RIP `movsd`/`divsd` operand. Grant the conservative numeric
   binding only for a single pool occurrence with at least one scoped operand.
   Do not infer the reference constant's name or semantics. This is not a census
   of all constants in the component.
8. Decode E8 rel32 only at verified instruction boundaries in scoped FDEs. Count
   an edge only when its computed destination is another scoped FDE's exact start.
   Indirect calls, tail jumps and other callees are outside this edge denominator.

Addresses are ELF VAs, instruction starts include their prefixes, and ends are
exclusive. Every byte record supplies a file offset. In this target `.text` VA is
file offset + `0x1000`; `.data.rel.ro` VA is file offset + `0x2000`; `.rodata` VA
equals file offset. No Ghidra load base is assumed. No comparison operands or raw
bytes are masked. No full binary decompilation was attempted.

## Reference provenance and overlap review

The can1357 tree is **unlicensed inferred reference code**, used only for search
leads, not copied into an implementation. The repository gitlink and
`provenance/sources.json` pin `999556f6e0a474b8312db96ec3149e1c44e97c23`.
`git submodule status` reports the submodule at that commit. These are the observed file SHA-256 values:

| File under `references/can1357-hl/l1/spot_clearinghouse/` | SHA-256 |
| --- | --- |
| cl_trait.rs | `2260f2a02be7de2d9f9ae38cfa3079722b229e254382110d80fe30445a1c6650` |
| impl_outcome.rs | `392d0488554f68f4b17da8fa1ae48c86390f921eb78ed285d9c630fa84201690` |
| spot_clearinghouse.rs | `df433100874bacc993ed24f56821c06e58156c2f7235c6baf5dfc22af45fa341` |
| types.rs | `7b0e7c0d7963860bfb7c0b5b63b466299c9c7b6ba473dbef1e6048462e9f5f1d` |

`research/catalogue/components.json` assigns these four files to `risk`;
`research/catalogue/seed-candidates.json` has no seeds for these files. No seed
address was used as a boundary. The existing
[InfoRequest packet](../RE-012-info-request-path/README.md) supplied a methodology
reference. The startup, l1-evm and clearinghouse-oracle inventory packets named in
the request are absent from this checkout; this packet does not cite their contents.

The existing [spot decimal admission packet](../RE-004-spot-token-decimals-94/README.md)
and [spot wei scale packet](../RE-004-spot-wei-scale-family-94/README.md) were reviewed
for overlap. Decimal guards, pow10 tables, wei scale, rounding and their helper
semantics are excluded here. Nothing in existing work-item directories or tools
was edited. No progress, catalogue or gate file was changed.

## Packet and controls

| File | Role |
| --- | --- |
| `inventory.json` | Target-bound census, raw Location/relocation/FDE bytes, LEAs, probe positives and negatives, constants, call edges, producer source hashes |
| `disassembly.json` | Full raw objdump output for all 15 scoped FDE ranges; version, commands, status, no truncation |
| `README.md` | Scope, provenance, method and reproduction |
| `RESULT.md` | Findings, limitations, validation and verdict |
| `verify.py` | Exact manifest whitelist (including RESULT.md), hashes, target digest, regeneration, independent pinned facts; works under `-O` |
| `MANIFEST.sha256` | Hashes of every packet file except itself |

The 30 tests include fixed target expectations and actual byte corruption, rather
than just testing invented successful examples. Controls cover digest mismatch
before disassembly; bad ELF mappings; Location pointer, length, line, column and
path corruption; relocation duplication/symbol errors; FDE/CIE corruption and
end-exclusive bounds; truncated/gapped/wrong-byte disassembly; instruction-interior
LEA/call patterns; signed rel32, wrong opcodes and non-start targets; pointer-length
mismatch, clobbers, branch interference and wrong call forms; counted-prefix
length/content/marker corruption; nonunique/changed constants; unresolved literal
controls; manifest omissions, duplicates, traversal, symlinks, extra files and
modified prose; and verifier fact corruption. Lower-level mutation tests exercise
parsers directly. The public generator never accepts a changed digest.
