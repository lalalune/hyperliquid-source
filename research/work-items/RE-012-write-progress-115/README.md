# RE-012: node115 prepared-write scalar transition

Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
ELF virtual addresses, no rebase or masks. Base 8fd8db680ec4bfef40996e5616bce3d5156d0b86.

Question: once a prepared slice reaches the selected write loop, how do raw
helper outputs change its pointer, remaining count and inner state, and does
resumption repeat the counter charge?

`src/node115-write-progress` is an independently authored dependency-free Rust
scalar implementation. Its numeric routes and validation adapter are NEW API,
not the original Rust Result/future ABI. No pointers are dereferenced by the
safe scalar API. `None` means no qualified inner-byte write, not native tag0.

## Original evidence and ownership

Complete shared sender context 0x2b7a290..0x2b7b523:4755bytes/914 instructions.
Complete helper context 0x5cdfc90..0x5cdfe4b:443bytes/120 instructions.
The 5198 bytes/1034 boundaries are exports, not implemented-byte coverage.
Full body hashes and raw FDE/CIE records are in rust-validation.json. The
selected helper call, opaque error-conversion call, actual state tables,
resume jump and unique send/__errno_location dynamic bindings are re-read.

PR2068 owns prefix/numeric poll-outcome research; PR2076 owns header admission
and chunk planning; PR2117 owns greeting deadline selection. Their shared
sender is context here, not a new whole-function ownership claim. PR2123's
filesystem write loop at0x5ca5110 is a different path. This contribution is the
conditional prepared-slice progress kernel; framing, deadlines and read policy
are not reimplemented. Historical own #94 work was a lead only; the #115 owner
is larger and its status branches differ. No retired address is relabeled.

## Reproduce

Use an authenticated retained target, Python3.12, Capstone5.0.6 and direct
Rust1.94.1 with the Linux x86-64 std target. From the repository root:

```sh
python tools/tcp_write_progress115.py --rustc /path/to/rustc --out work/write-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-write-progress/Cargo.toml
HYPERLIQUID_WRITE_PROGRESS_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_tcp_write_progress115.py -v
```

The output directory must be fresh. Only newly compiled ELF REL own code is
interpreted using the unchanged shared instruction evaluator; no captured
node/helper instruction is executed or interpreted. Captures are rejected as
objects or compiler paths before subprocess dispatch. No live socket is used.
The oracle is a same-author explicit scalar lowering of pinned native branches,
not an independent peer implementation or an observed IO trace.

3136 boundary combinations compare all six synthetic output words. Six real
source corruptions are separately compiled and produce mismatches; four real
native immediate patches both fail the target guard and change the deliberately
relaxed scalar lowering. Eight additional native branch/counter/table/import
corruptions are refused by focused checks. Repeated own objects are identical.
Compiler options, hashes, original exports and concrete witnesses are retained.
The original and own extents differ; no aligned/normalized byte comparison or
registered byte-window credit is claimed.

## Limits

`charge` is a separate initial-entry operation, not a charge on every advance.
Helper status/value pairs are conditional synthetic inputs. Readiness, send,
retry/CAS races, scheduler, cancellation, unwinding, clock/error conversion,
actual future layout and network delivery remain unclosed. Alias preservation
across the opaque helper and ordinary control-flow entry are assumptions.
No full sender/socket implementation, target code identity, integrated node,
hosted CI or component gate is claimed. See PROOF.md and validation.md for the
bounded derivation and exact local check results. New source and notes are MIT;
original evidence retains its existing rights. No inferred reference code is
copied, and imported inputs/pins are unchanged.
