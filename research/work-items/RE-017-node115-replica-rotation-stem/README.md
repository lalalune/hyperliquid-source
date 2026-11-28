# RE-017 Node #115 replica rotation filename and row handoff

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Analysis base: `2da45cb0a761cff6b478e40421699857d87a94df`.
- Coordinates: ELF virtual addresses within captured DWARF FDEs.

The [capture-path packet](../RE-017-node115-replica-capture-path/README.md)
establishes the initial replica filename and the
[entry-checkpoint packet](../RE-017-entry-checkpoint-115/README.md)
establishes the sink's bucket arithmetic. This packet traces which value
becomes the rotated filename and how the old/new line writers handle the
incoming record.

## Filename stem

Builder `0x595ac30` saves its supplied initial height from R9 at
`rsp + 0x58` and stages it for the final formatter at `0x595ae65`.
The path descriptor at `0x440e47` adds two slash-separated components to
the prefix. Its argument slots use the established date formatter and
unsigned decimal formatter.

When the already-initialized sink `0x595a6b0` sees an unsigned bucket
greater than its saved marker, the selected rotation uses that same
descriptor. Here the third argument comes from `rsp + 0x58`, which
`0x595a715` just filled with the computed bucket in R14. The date comes
from the fresh clock result converted through `0x64e0ab8`. The prefix
pointer/length comes from the sink at `+0x8/+0x10`. The formatter output
is copied from `rsp + 0x90` to the new liner constructor's input, and
the bucket word is also saved as the sink marker at `+0x68`.

Thus the rotated file uses the shape
`<base>/data/replica_cmds/<prefix>/<current date>/<bucket>` with
`bucket = floor(max(n - 1, 0) / 10000) * 10000` for the observed
second argument `n`. If consecutive rows reach the sink and the
stored marker is lower, height 10001 leads to stem 10000, while
10002 stays in that bucket. Initial height, missing rows, supplied
marker and received heights can differ. An offline extractor can use
the stem to locate likely files and still use the explicit JSON
height to choose a row.

## Old and new liners

On the selected nonzero-flag roll, `0x595aaed` constructs the new
line writer and `0x595aaf6` calls the old writer cleanup before the
new liner state is stored. The old cleanup `0x5951600` calls
`0x1533e80` with its buffered handle. With pending bytes, the latter
passes its saved descriptor, buffer plus sent count, and remaining
length to imported `write`. The old initialized branch then reaches
imported `close` at `0x5951658`. Returned flush errors take a disposal
call before cleanup continues.

At `0x595ab43` the sink passes the incoming record pointer saved
at entry to `0x50e2f80` with the installed liner. Its successful
serialization appends byte `0a` and calls the buffered writer.
The sink then calls the flush helper on the new liner. This is
ordering of the selected native calls. Actual file creation, successful
writes, completeness of an archive, filesystem durability and
checkpoint/state-root pairing remain unverified.

## Reproduce offline

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replica-rotation-stem/verify.py
(cd research/work-items/RE-017-node115-replica-rotation-stem && sha256sum -c MANIFEST.sha256)
```

[Instruction windows](windows.txt) preserve the LLVM commands and
bytes. The [offline output](offline-log.txt) records the digest,
FDEs, relocation and import bindings, and rejected operand mutations.
No captured code was executed.
