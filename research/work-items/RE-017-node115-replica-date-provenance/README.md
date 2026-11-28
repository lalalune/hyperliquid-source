# RE-017 Node #115 replica rows and directory dates

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Analysis base: `2da45cb0a761cff6b478e40421699857d87a94df`.
- Coordinates: original ELF VAs within captured DWARF FDEs.

The [replica capture path](../RE-017-node115-replica-capture-path/README.md)
establishes the date-bearing filename. The
[entry bucket gate](../RE-017-entry-checkpoint-115/README.md) establishes
when a rollover occurs. This packet identifies the directory date's
clock source and distinguishes it from the serialized row timestamp.

## Directory date on the selected roll

At `0x595a722` the roll branch calls clock adapter `0x1629690`. The
adapter passes clock ID zero through `0x5c842e0` to the authenticated
`clock_gettime` import. It takes the elapsed time relative to the zero
timespec and decomposes the seconds into 86,400-second days plus seconds
within a day. It adds the Unix epoch's day ordinal 719163 and converts
through `0x1628f50` to the packed calendar day saved at output `+0`.
Seconds within that day and subsecond nanos go to output `+4` and `+8`.

At `0x595a733` the sink supplies adjustment zero before calling
`0x1629fb0`. On the valid seconds-of-day range `0..86399`, the first
multiply/shift fold in that helper stays in `0..65535`. Its next
shift gives zero, and the remainder is already nonnegative. The
helper's zero-day path therefore copies the packed day through
unchanged. The date formatter at `0x150ce90` reads this packed day
and supplies the six bytes `%Y%m%d`. The resulting path date on
this branch is the UTC wall date at rollover.

## Row time on an existing liner

An incoming bucket at most the retained marker branches at
`0x595a700` directly to `0x595ab27`, bypassing the date conversion
and path formatter. This path reuses the current liner even if the
realtime day has changed. It still samples realtime at `0x595ab2f`
and sends that sample as the second argument to `0x50e2f80`, which
forwards it to the buffered liner call.

The JSON serializer receives the separate original record pointer
saved by the sink at entry. It inserts `abci_block.time` from
the block member at `+0x38`. That is a field in the supplied block,
independent of both the directory date and the timestamp passed to
the liner.

A row can therefore have a block time in one day and reside in a
filename dated for another day. A same-bucket append across UTC
midnight stays under the already-selected directory. A rollover
instead samples a new UTC wall date. These identities constrain
offline row lookup. They do not imply that a particular archived
file exists, that a row was delivered, or that a checkpoint and
subsequent state root align.

## Reproduce offline

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replica-date-provenance/verify.py
(cd research/work-items/RE-017-node115-replica-date-provenance && sha256sum -c MANIFEST.sha256)
```

The [raw offline log](offline-log.txt) records the validated clock
import, FDE bounds, zero-offset range bound and rejected controls.
[LLVM instruction windows](windows.txt) show the selected operands.
No captured code was executed.
