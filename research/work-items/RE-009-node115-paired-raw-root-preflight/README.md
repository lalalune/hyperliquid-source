# RE-009 #115 adjacent raw-root capture eligibility

The checkpoint replay acceptance check needs independent raw-root rows at heights H and H+1. The open [persisted cadence change](https://github.com/lalalune/hyperliquid-source/pull/7302) initializes the replay fixture's cadence. The fixture's Boolean check accepts multiples of 10,000 unconditionally and omits the selector's context mode and freeze invariants. That check is insufficient for deciding whether to look for an independent row at either height. This packet follows the selected slow engine's shared root gate and provides an offline preflight for a pair of materialized states.

## Selected #115 route

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The constructor call at `0x5a0901f` and the post-comparison block finalizer call at `0x5a05fc9` both reach the selector at `0x5a07ec0`. It reads the state pointer at context `+0x450` and the height at state `+0x28`. The eligible path calls `0x548dad0` at `0x5a07fce`. That bridge copies state `+0x28` into the writer record before calling `0x4e3a7a0`. The subsequent call at `0x5a07fe5` uses the same height for local root history. The persisted capture layout and separate quorum sink are described in the [raw ABCI hash sink packet](../RE-017-node115-abci-hashes-file/README.md).

| Order | Selector observation | Preflight result |
| --- | --- | --- |
| 1 | If height is outside the 10,000-block cadence, low DWORD tag at state `+0x10e8` equals 1 and target at `+0x10f0` is below height, branch at `0x5a07f13`. | Invariant exit before checking mode |
| 2 | If reached, mode at context `+0` equals 2 and returns the empty sentinel at `0x5a07f2e`. | Skips mode 2 |
| 3 | If reached, active target below current height takes the second invariant branch at `0x5a07f58`. | Invariant exit after checking mode |
| 4 | The mandatory 10,000-block cadence or active equal target sets `bpl`; `0x5a07f83` bypasses interval division. | Eligible from 10,000-block cadence or freeze |
| 5 | Otherwise `0x5a07f85` reads the materialized interval from state `+0x39c8`. Two unsigned DIV paths converge on the same zero-remainder decision. | Eligible on a zero remainder, skips on a nonzero remainder, reports invalid materialized cadence if the reached divisor is zero |

The fixed cadence compiles to a multiply by `0xd288ce703afb7e91`, a right rotation by four, and an unsigned comparison against `floor((2^64-1)/10000)+1`. Values that pass have the low four product bits clear. The multiplier's inverse modulo `2^64` is 625, so each accepted rotated value `k` comes from height `k * 16 * 625` without wrap.

## Reproduce offline

Run from repository root with the pinned node artifact in place. The verifier reads ELF data and compares the selected spans against function extents. It runs the independent Python model with synthetic pairs and checks unsigned boundaries. See [offline log](offline-log.txt).

```sh
packet=research/work-items/RE-009-node115-paired-raw-root-preflight
python3 -B "$packet/verify.py"
python3 -B "$packet/preflight.py" 10000 --at-h 0 0 0 1000 --at-h1 0 0 0 1000
```

Each state argument supplies mode, the low 32 bits of the freeze tag, freeze target and the materialized cadence. Freeze target is ignored for inactive tags. H and H+1 receive separate inputs so changes made during replay cannot be hidden by reusing the checkpoint's parameters. The sample reports H eligible and H+1 skipped. A custom per-height cadence or active freeze target can make H+1 eligible. A filename or default cadence alone cannot establish either status.

Eligibility means the selected gate reaches the root helper. Capture success still depends on the writer, retention and access to the correct archive. A qualifying archive row and a reconstructed root remain necessary at each height. This packet establishes no historical row availability or root equality. The synthetic inputs are evaluated by Python and the captured node is only read as ELF data.
