# RE-013: metadata failure bit and publication admission

This closes the flag-producer portion of
[the lifecycle packet's first unresolved edge](../RE-013-visor-lifecycle/unresolved-edges.md).
Under valid four-mode input, ordinary helper returns and explicit storage
preservation, a fresh non-tag-2 metadata result supplies a 0/1 byte. Download
XORs that byte with 1; publication rejects zero. Consequently, the arm that
skips the explicit 32-byte comparison cannot reach the later publication
operation calls. The admitted arm must pass that comparison.

Two boundaries are essential: arbitrary byte3 would skip the comparison and
pass the nonzero publication gate, and metadata tag2 can leave an old cache
in use. The result therefore requires both the producer's 0/1 domain and the
selected fresh-result copy corridor. It is not a quorum or cryptographic
verification claim.

[PROOF.md](PROOF.md) gives the four producer modes, every flag-store family,
caller copies, comparison packing, operation ordering, cleanup requests and
opaque dependencies. All coordinates refer to the authenticated visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`
(8,305,392 bytes), research base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

| Retained scope | Bytes | GNU/LLVM rows |
|---|---:|---:|
| Three complete producer/download/publication FDEs | 9,722 | 1,748 |
| Three selected lifecycle copy corridors | 733 | 130 |
| Total | 10,455 | 1,878 |

The full 23,809-byte lifecycle FDE is provenance metadata only. No complete
caller theorem or additional recovered-byte credit is claimed. Prior
[PR45](https://github.com/lalalune/hyperliquid-source/pull/45) owns the lifecycle
observations; metadata loaders, prepared-path helpers and their policies stay
opaque. The independent packet changes no shared tools, Rust implementation,
component acceptance or source-built progress gate.

From this directory, on the documented native-tool versions:

```sh
python3 -B collect.py --out /tmp/visor-metadata-new-evidence
python3 -B verify.py
python3 -B -O verify.py
gzip -dc observed/metadata.llvm.txt.gz
```

Output directories must be new. Defaults are GNU objdump
`/opt/homebrew/opt/binutils/bin/objdump` and Apple LLVM `/usr/bin/objdump`.
No captured executable is run: both tools read one private, read-only,
digest-checked snapshot. LLVM exports are deterministically compressed to
avoid duplicate large review text. `observed/records.json` binds full native
exports, FDE/CIE records, call-slot relocations and structural certificates;
`flow.tsv`, `calls.tsv` and `frame-review.tsv` support manual review.

The scripts and argument are independently authored. The collector imports
the repository's MIT-licensed `tools/elf_index.py` and `tools/fde_extents.py`
for existing section/unwind parsing; their hashes are recorded. It does not
depend on another unmerged packet. [VALIDATION.md](VALIDATION.md) distinguishes
byte/graph/algebra checks from the conditional semantic argument.
