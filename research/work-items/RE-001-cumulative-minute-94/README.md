# RE-001: cumulative-minute conversion, narrowing and inclusive boundary

- Component: foundation time utilities. Question: which actual node94 ranges
  use `base/src/cumin.rs:21:13`, and what domain do their local conversion
  guards accept? This is function/range/xref research under RE-001, not recovery
  of the surrounding callers or a claim that source types have been recovered.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Base and reference pins:
  `1f8c67c63ca4794c9689235471c60297f8a5c985` (pins unchanged).
- Inferred reference `base/cumin.rs` supplies search leads only. Its `u16` and
  cumulative-minute labels do not prove machine widths, rounding, guard order,
  valid input states or inlining. No unlicensed implementation is copied.
- No captured binary execution, new Rust implementation or progress gate.

## Result

Eight selected actual FDEs contain **14** instances of one conversion and
reference the same assertion Location. The enclosing FDEs occupy **36,214
bytes**. Six contain a pair of conversions; two contain one. These counts
cover the eight validated ranges below, not all functions or calls in the ELF.
The packet retains complete native disassembly of those ranges so that each
small selected expression is decoded from an actual function start.

| FDE start | Exclusive end | Bytes | Selected conversions |
| --- | --- | ---: | ---: |
| 0x26ff460 | 0x27000a2 | 3138 | 2 |
| 0x2700390 | 0x2701d93 | 6659 | 2 |
| 0x4925220 | 0x4925f0c | 3308 | 1 |
| 0x4925f10 | 0x4926dac | 3740 | 1 |
| 0x4ce8b40 | 0x4ce9662 | 2850 | 2 |
| 0x4ce9670 | 0x4cea192 | 2850 | 2 |
| 0x4cea760 | 0x4cec25c | 6908 | 2 |
| 0x4cec260 | 0x4cedcc9 | 6761 | 2 |

The selected input load is **32-bit**, with zero extension. Each expression
computes, with logical right shifts and the retained register assignments:

```
h = (n * 0x91a2b3c5) >> 43
m = (n * 0x88888889) >> 37
q = (m * 0x08888889) >> 33
r = 60*h + m - 60*q
```

Three finite reciprocal certificates establish `h=floor(n/3600)`,
`m=floor(n/60)` for **every u32 n**, and `q=floor(m/60)` for every m up to
`floor(u32::MAX/60)`. For each remainder class the certificate checks the
largest quotient; with nonnegative reciprocal error it bounds every smaller
quotient. `floor(floor(n/60)/60)=floor(n/3600)`, so `r=floor(n/60)`.
The multiplications fit 64 bits and all multiply-by-60/sub/add intermediates
fit 32 bits over this domain. Although `imul` is the encoding, low 64-bit
products followed by logical shifts retain the required unsigned product;
no signed overflow flag is consumed here. The register-level sequences, not
just the constants, are retained in `selected-windows.json` and checked against
fresh native decoding in the generator.

The observed order is **unsigned r > 65535 first**, then **unsigned r >= 1441**.
The second edge leads to the shared `cumin <= 1440` assertion block. Thus,
for a raw u32 n reaching one of these local blocks:

| Raw n | Local result |
| --- | --- |
| 0..86459 | both local guards pass |
| 86460..3932159 | cumin assertion edge |
| 3932160..4294967295 | earlier narrowing-failure edge |

For a valid seconds-within-day value 0..86399 the result is 0..1439. The
inclusive 1440 boundary also locally accepts 86400..86459. This does **not**
assert those extra raw values are reachable, that upstream time constructors
accept them, or that passing these two guards implies acceptance by the
surrounding function. There is no off-by-one defect claim: the reference's
inclusive assertion is present in this target. The new evidence establishes
its actual inlined arithmetic, local guard order, domains and range ownership.

## Coordinates, bindings and files

`frames.txt` preserves eight actual GNU FDE records; `records.json` gives
VA ranges, corresponding file offsets, body sizes and SHA-256s, all fourteen
instruction windows, branch destinations and complete division certificates.
The `.objdump.txt` files preserve full enclosing disassemblies. They contain
uninterpreted paths outside this bounded question; retaining them does not
claim to have recovered those paths. The method consumes every instruction
byte from FDE start to end and verifies all selected expression starts and
text against the retained specification. No normalization masks are used.

Each assertion block loads message VA `0x21adef`, length 31,
`assertion failed: cumin <= 1440`; Location slot `0x566cb50` has RELATIVE
addend `0x1e3851`, path `/home/ubuntu/hl/code_Mainnet/base/src/cumin.rs`,
length 46, line 21 column 13. Call slot `0x576e108` has RELATIVE addend
`0x157b7f0`. The call target is bound but its entire helper closure is not
analyzed or assigned a recovered Rust API name. Earlier narrowing-failure
edges are retained in disassembly; their full error/helper semantics are
outside the claim. Concrete caller types and source function names remain
unresolved.

## Reproduction and validation

From the repo root, materialize pinned LFS inputs and expose native GNU binutils:

```sh
python3 -B tools/cumulative_minute_static.py --output work/cumulative-minute-94
python3 -B tests/test_cumulative_minute_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-cumulative-minute-94/SHA256SUMS
```

Host tools: Python 3.12.14, GNU readelf/objdump 2.47.20260726. The generator
reads and authenticates one complete snapshot before analysis, then gives that
same snapshot to native tools via a private temporary file. Temporary paths
are replaced with `<authenticated-node94>` in exports. It uses `readelf -wf`
and `objdump -d -M intel --insn-width=16 --start-address=... --stop-address=...`.
No captured executable is spawned or emulated. Independent transient Capstone
5.0.6 consumed all eight ranges in 673/1313/655/761/597/597/1354/1315
instructions respectively, agreeing with their complete byte extents.

Five focused tests cover real range/source bindings; independent ordinary
division at each certificate extremum and six wrong multiplier/shift controls;
all 86,460 locally accepted raw inputs and adjacent 1440/1441/65535/65536
boundaries; **39** actual-byte instruction/data/Location corruption controls
below the input hash gate; and fresh native packet regeneration. The arithmetic
checks model the decoded expression and do not run the target. The new tool
reuses the existing MIT `foundation_millis.prove_division` and `decode_export`
helpers rather than adding another general unwind decoder or reciprocal prover.

Required suite and reproduction results are recorded in the PR after completion.
The SHA manifest covers every durable packet file and both new source files.
Original imports, captures, reference pins and progress gates remain unchanged.

## Remaining gaps

No independent Rust build, binary comparison, runtime equivalence, whole-tree
caller census, type/ownership recovery, valid timestamp-state proof or transitive
helper closure is established. The selected range census is not a denominator
for recovered functions in a component. Next question: determine which time
constructor supplies the input words at these call sites and whether the extra
raw minute-1440 interval can occur; this requires separate caller evidence.
