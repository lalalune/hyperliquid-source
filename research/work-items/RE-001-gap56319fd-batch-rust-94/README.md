# Rust implementation of the same #1043 scalar arithmetic family

Task: RE-001; bounded independently authored numeric implementation under
`src/`, not a new algorithm/function-range claim. Target is node #94,
91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The original sixteen source/evidence files at
`2743f6ae9237405d46a93dc96ddb646a55819e89` remain byte-identical. This sibling
packet deliberately leaves the original flat evidence inventory unchanged.
It amends the same #1043 outcome, not a second PR or new native-window gain.

## Established family and independent implementation

The [original proof](../RE-001-gap56319fd-variable-records/PROOF.md) binds all
1,269 bytes / 324 instructions in candidate `0x56319fd..0x5631ef2`, body hash
`00933a9b47d97b4ac90e7845469b6a4b0e3d76357432bf6e86f65d7bd215c425`.
Its existing `0x5631a6c..0x5631afe` scalar slice is 146 bytes / 37 rows,
hash `dcbf2ba4a37be185cdc9ea538e40957525e4df8592329ae367f5d8c5608eb34a`.
These are credited existing witnesses, not additional recovered bytes.
The source-byte-bound prologue identifies fixed E0..E3 and L separately from
current I0 and O0..O3. No original source ownership/type is assigned.

`src/node94-record-batch-limit/lib.rs` implements all four modular output
differences, the modular input difference, unsigned floor quotients, their
minimum, the modular stop and actual numeric equality guard. The safe
`no_std` API uses direct Rust unsigned division, not transplanted code.
It has no pointer, allocation, table, I/O, target call or unsafe operation.

The original all-u64 proof establishes:

```text
N = 2^64
M7 = 0x2492492492492493; 7*M7 = N+5
h = unsigned_high64(d*M7)
q7 = (h + ((d-h) >> 1)) >> 2 = floor(d/7)
M10 = 0xcccccccccccccccd; 10*M10 = 8*N+2
q10 = unsigned_high64(min(r0,r1,r2,r3)*M10) >> 3
    = floor(min(r0,r1,r2,r3)/10)
q = unsigned_min(q7,q10)
stop = low64(O3+4*q+q)
stop == O3 iff q == 0 iff d<7 or some r_i<10
```

Monotonic floor division permits the equivalent production minimum of all
four individually divided remainders. `q <= floor((N-1)/10)` implies
`0 <= 5*q < N`, so even a wrapping final ADD cannot produce a false
nonzero-quotient equality. This is a total scalar result. Turning a
difference into available memory or `q` into a loop capacity still requires
the original unverified nonwrapping bounds and other explicit premises.

## Oracle and protocol

The runner calls the unchanged static producer. That authenticates one full
original descriptor/mmap before and after analysis; GNU objdump receives only
the 1,269-byte private raw span. Every retained row is bound to actual bytes.
The runner binds the ten scalar leaves of its finite expression DAG, then
evaluates only 64-bit constants/sub/add/MUL-high/MUL-low/logical-shift and
unsigned selection. Unbound load/effect terms fail. This is closed
mathematical scalar evaluation, not a concrete register/memory/CPU model.
The expected path has no production division or Rust output dependency.

The generated production harness reads only ten-value input lines and calls
the externally linked actual library. Expected results remain a separate
Python comparison stream. Neither reviewed production code nor harness
reads them; OS sandbox isolation is not claimed. One ordinary Rust test
also checks the fixture in each profile. The runner rejects an edited or
empty fixture against fresh authenticated extraction before compiling.

There are **3,288 distinct scalar cases**. Each lane is separately the only
limiter; zero/6/7 and 9/10 thresholds, high 7/10 multiples, unsigned maxima,
both subtraction underflows, ties, positive-q stop wrap and deterministic
ten-word cases are included. These are numeric cases, not live successful
loop entries or recovered-function denominators. Native M7-1 at d=7 and
M10-1 at r=10 both yield zero instead of one before validation rejects the
changed actual operand. Captured input bytes remain unchanged.

Ten Rust mutants target distinct native relations: wrong input divisor,
wrong output divisor, each of the four omitted lanes, saturating distances,
wrong stop factor, saturating stop and wrong numeric guard. Every claimed
control must compile, produce a differing independently compared value and
fail an actual compiled semantic assertion. Mere compilation failure earns
no semantic-control result. Raw stdout/stderr, argv and exit codes are kept.

## Real component build and preservation

The existing independently verified research compiler is rustc 1.94.1,
repository pin, not the original node compiler. Its official archives,
publisher sidecars, inspected payloads and licenses were already retained
outside the repository; this amendment installs nothing. `TOOLCHAIN.json`
records actual identities. There is no invented Cargo graph/manifest,
dependency, lockfile or stub. Direct `rustc` uses explicit host linker,
edition, overflow-checks, optimization, metadata and remapped source paths.

The runner builds unoptimized and optimized real `.rlib` production code,
ordinary Rust tests and the independent input-only comparison harness.
Two additional fresh optimized libraries are compared as raw bytes, without
normalization. This reproducibility concerns only our newly authored module
under the same research toolchain, never original binary identity. Transient
programs, libraries and mutant sources remain in owned `/tmp` output paths.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_record_batch_rust.py \
  --rustc /path/to/trusted/1.94.1/rustc --output /tmp/batch-new --controls
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_node94_record_batch_rust.py -v
make 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

The observed run passed **3,288 production cases in each of two profiles**,
with **one ordinary Rust corpus test per profile**. Ten mutants compiled and
failed actual assertions; their independent production mismatch counts in
the listed order are **577, 2427, 629, 607, 613, 609, 2865, 3088, 1608, 73**.
Two fresh optimized own libraries are raw-equal, **12,412 bytes** each,
SHA-256 `8adaf74f81f72ef8800b37c8c7f38ff980b9e9361b1818a8f6c539f63a2a2edb`.
Seven target-grounded Python controls passed under normal and optimized
Python. Those counts are separate from final repository checks.

`RESULT.json` records observed component counts/tool/source identities.
`RAW-LOGS.json.gz` losslessly retains all **62 subprocess records / 124 raw
stdout-stderr streams** as UTF-8 text with lengths and SHA-256, compressed
with gzip for size. `RAW-LOGS-ENCODING.json` pins compressed and decoded
bytes; no comparison output is normalized. For example:

```python
import gzip, json
from pathlib import Path
logs = json.loads(gzip.decompress(Path("RAW-LOGS.json.gz").read_bytes()))
raw_stdout = logs["commands"]["debug-production-run"]["stdout"]["utf8"].encode("utf-8")
```

Final frozen-source independent review and exact-commit required
checks are reported in the amended PR only after completion. Component
build evidence is not silently relabeled as an aggregate or hosted result.

## Limits and next obligation

The API is newly chosen Rust and operates on raw u64 words. It does not
implement original state/frame writes, table records, BSF/refills, loop
termination/progress, pointer lifetimes/regions, the subsequent three input
ordering guards, original types/ABI/compiler or full candidate behavior.
A false zero guard alone does not establish original inner-loop admission.
Original caller and runtime table invariants remain missing. No new native
coverage, original byte equivalence, full component or milestone is claimed.
New code/docs are MIT; captured and imported material retains original rights.
No unlicensed inferred source was read or copied. Captured execution, live
network/chain actions and signing are absent. The useful next step remains
qualifying callers/runtime data before integrating this scalar family into
a larger reconstructed implementation.
