# RE-008: consensus-error outer construction and caller contract (node/94)

This packet recovers the outer construction paths of `0x4752890`: **19 direct
name values, 12 ordered field builders, and 11 explicit-index helper calls**.
It adds the 31 outer paths left unresolved by the earlier tag packet, the
selected seven helper boundaries, and a concrete consumer at `0x4aa71ba` with
its upstream `Ok`/`Err` branch at `0x49c0f87`.

The result is a conditional raw-memory/dataflow contract, not a recovered Rust
type or bincode schema. All 42 outer arms are accounted for; field-builder,
map, converter, allocator and destructor internals are not all recovered.
In particular, a caller's 72-byte copy does **not** establish that all 72 bytes
are initialized or active for every variant.

## Review first

- [PROOF.md](PROOF.md): premises, construction/result tables, exact caller
  consumption, index limits and remaining obligations.
- [contract.json](contract.json): all 42 selectors, ordered field arguments,
  direct stores, selected helper calls and fixed witnesses.
- [collect.py](collect.py) and [verify.py](verify.py): independent native decode
  comparison and corruption controls. Neither executes or interprets captured
  instructions.
- [observed/records.json](observed/records.json): actual FDE/CIE and LSDA records,
  relocations, hashes and evidence index. [observed/cfg.tsv](observed/cfg.tsv)
  retains the complete structural basic blocks once.
  A `-` successor field means no recorded structural successor; it does not
  assert termination or resolve an opaque indirect transfer.

## Identity and prior work

- Component: `consensus`; bounded question: outer construction, raw result
  stores, and the confirmed caller consumption.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes.
- SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Research base: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Coordinates: linked ELF virtual addresses, half-open ranges.
- Host: Darwin 27.0.0 arm64, Python 3.14.3. No environment installation.
- Source/reference boundary: independently authored packet scripts/docs; no
  new can1357 source use. The prior packet above records its own reference pin.
- Claim status: byte observations plus conditional manual dataflow inference;
  opaque-helper/source-type/wire claims remain unresolved.
- Primary prior evidence: [RE-008-consensus-error-tags-94](../RE-008-consensus-error-tags-94/README.md)
  ([PR #282](https://github.com/lalalune/hyperliquid-source/pull/282)). Its
  42-name association, three formatter copies, and 11 index/name setups are
  credited inputs. They are not new discoveries here. This packet resolves
  the remaining outer construction categories, not the prior packet's wire
  enum or full payload-layout questions.
- [PR #1280](https://github.com/lalalune/hyperliquid-source/pull/1280) concerns
  block admission; no reconstruction crate or shared source is changed here.

## Validation and reproduction

The retained evidence covers **14 full FDEs, 12,336 instruction bytes and 2,584
normalized instruction rows**. GNU and LLVM agree on every selected byte and
instruction boundary after joining only standalone LLVM `LOCK` prefix rows.
`verify.py` passes **281 corruption controls** and two complete regenerations.
Normal and `python3 -O` verification produce the same JSON, retained once in
[validation.json](validation.json). [MANIFEST.sha256](MANIFEST.sha256) binds the
packet files other than itself. A control mutates
an unselected instruction byte: it passes the selected-witness subset and
fails the full native-byte comparison, making that subset's limit explicit.

From this directory, with the captured artifact and the already available
native tools:

```sh
python3 -B verify.py
python3 -B -O verify.py
python3 -B collect.py --out /tmp/consensus-construction-new-evidence
```

The output directory must be new. Defaults are GNU objdump
`/opt/homebrew/opt/binutils/bin/objdump` and Apple LLVM objdump
`/usr/bin/objdump`; `--gnu` and `--llvm` allow explicit paths. Recorded versions
are GNU 2.47.20260726 and Apple LLVM 21.0.0. Exact retained-output comparison
also binds the native formatter/tool versions.

GNU exports stay readable, for example
[constructor.gnu.txt](observed/constructor.gnu.txt). The full second-provider
outputs use deterministic gzip to avoid duplicate disassembly in review:

```sh
gzip -dc observed/constructor.llvm.txt.gz
```

`records.json` records raw and stored export SHA-256 values. Verification checks
both, decompresses LLVM, compares exact bytes/partitions, and regenerates every
retained file twice from one authenticated private read-only snapshot per run.
The original artifact is never executed. No emulator, instruction evaluator,
network probe, project installation, or full project suite is used.

## Limits and use

No Rust implementation or compiled-code equivalence is claimed or measured.
Before this packet, the prior tag packet left 31 construction arms unresolved;
they now have a bounded outer construction classification and caller contract.
No component acceptance gate or progress update is requested.

This gives a downstream reconstruction a concrete distinction between raw
construction errors (`0x8000000000000005` plus payload), direct name values
(`0x8000000000000003`), and opaque field/helper results. The confirmed caller
branches on that distinction before wrapping/copying a result. It prevents
mistaking the already-known ECX case index for demonstrated wire bytes.

The proof assumes valid accessible storage, non-aliasing live objects, normal
helper returns with the stated preservation conditions, and a valid selected
dispatch domain. TLS, allocator, imported `memcpy`, map and cleanup dependencies
remain explicit. No universal ABI equivalence, malformed-input safety,
ownership/lifetime closure, unwind behavior, consensus acceptance rule, or
handoff from `0x44adfa0` is claimed.
