# RE-009: where do the two RocksDB cache override words come from in node #94?

- Component: storage (`db/*`), bounded RE-009 static argument provenance.
- Target: `artifacts/node/94/hl-node`, release #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source revision: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No inferred reference source is copied. The earlier
  `RE-009-rocksdb-open-options-94` packet supplies the question and provisional
  state/checkpoint names; all instruction facts below are re-read from target.
- Claim status: observed register/stack transfers and direct calls; inferred
  Rust `Option<u64>` interpretation; unknown concrete entry values and their
  earlier producers. This is a partial result, with no gate requested.
- Scope: eight unwind-described ranges, the two paths from function-entry
  registers to the wrappers' cache selector, and immediate bundle selection.
  Excludes upstream callers of the entry functions, RocksDB implementation,
  filesystem/DB effects, target execution, #115 and Rust reconstruction.

## Reproduce

From the repository root on macOS arm64, using Python 3.11. The collector reads
the ELF, checks its SHA-256, uses the reviewed repository `elf_index` and
`fde_extents` parsers, and invokes installed LLVM only for static disassembly.
It never loads or executes the target and makes no network request.

```sh
python3.11 --version
xcrun llvm-objdump --version
python3.11 research/work-items/RE-009-rocksdb-cache-override-94/collect.py \
  --objdump "$(xcrun --find llvm-objdump)"
```

Observed disassembler: Apple LLVM 21.0.0, Intel syntax, default x86-64 decoding;
full version/registered-target output is retained in `llvm-version.txt`.
The exact per-range options are `-d --x86-asm-syntax=intel`,
`--start-address=<start>` and `--stop-address=<end>` from the table below,
followed by `artifacts/node/94/hl-node`. The executable is the value supplied
with `--objdump`; no shell is started by the collector.

Expected/observed collector result:

```json
{"direct_calls": 6, "fde_ranges": 8, "provenance_pins": 17, "rejected_corruptions": 23}
```

`records.json` binds full-range byte hashes, individual instruction bytes,
call sites, FDE record addresses and negative-control results to the target.
The `.llvm.txt` files retain every decoded instruction and raw byte in each
range, including failure/cleanup paths; there was no timeout or reduced
analysis profile. The script also checks that each pinned address is an LLVM
instruction start and each call is decoded to its recorded target. Repeated
collection with this LLVM version reproduced every generated file byte for byte.

## Evidence

All addresses are ELF virtual addresses; ends are exclusive. FDE extents are
unwind metadata, not proof of an exhaustive function census or source identity.
Each row has its own `<start-without-0x>.llvm.txt`.

| Role in this packet | Range | FDE record |
| --- | --- | --- |
| State entry | `0x37d4e30..0x37d5118` | `0x11aa9b0` |
| State collector | `0x3315c30..0x3315e8a` | `0x1168dbc` |
| State open closure | `0x3be4b40..0x3be4c8f` | `0x11e70d4` |
| State tuned wrapper | `0x3421980..0x3421e12` | `0x117954c` |
| Checkpoint entry | `0x459a4c0..0x459a7e2` | `0x12610bc` |
| Checkpoint collector | `0x489d280..0x489d460` | `0x12a2cec` |
| Checkpoint open loop | `0x4875ba0..0x4875f7e` | `0x129ff3c` |
| Checkpoint tuned wrapper | `0x42c70c0..0x42c75fc` | `0x122bdb8` |

### The pair exists at the entry functions, before collection

Both entry functions save their incoming RSI and RDX consecutively:

| Path | Save first word | Save second word | Capture pair pointer |
| --- | --- | --- | --- |
| State | `0x37d4e41: [rsp+0x68] = rsi` | `0x37d4e46: [rsp+0x70] = rdx` | `0x37d4ee0: rax = &stack[0x68]`; `0x37d4ee5: [rsp+0x10] = rax` |
| Checkpoint | `0x459a4d1: [rsp+0x68] = rsi` | `0x459a4d6: [rsp+0x70] = rdx` | `0x459a578: rax = &stack[0x68]`; `0x459a57d: [rsp+0x28] = rax` |

The complete entry decodes show no replacement store to either saved word
before the collector call. The optional logging branches return to the main
path without replacing them. This is a conventional static ABI/dataflow
reading; transitive implementations of the formatting/path helpers before
the collector are outside this packet.

State creates a three-word capture at stack `+8`: the incoming RDI at `+8`,
the pair pointer at `+0x10`, and bundle byte 2 at `+0x18` (`0x37d4ed6`).
It calls `0x3315c30` at `0x37d4ef4` with RSI pointing at that capture.
The collector preserves this pointer in R14 (`0x3315c3b`) and passes it as
RDI to `0x3be4b40` at `0x3315c9c`. Thus its allocation of a 16-byte output
vector is unrelated to the captured 16-byte override pair.

Checkpoint creates a five-word capture at stack `+0x20`: incoming RDI,
pair pointer, range start 0, range end 2, and packed bytes `00 01`.
The initialization is at `0x459a55a..0x459a57d`; the call to `0x489d280`
is at `0x459a58c`. The collector copies these 40 bytes into its own stack
`+0x30..+0x57` (`0x489d28e..0x489d2a3`), then passes the copied capture
as RSI to `0x4875ba0` at `0x489d2b0`. This copies the pair **pointer**;
it does not replace the two pointed-to words with a default.

### The pointed-to words reach the selector without per-bundle replacement

State closure `0x3be4b40` reads bundle byte `[rdi+0x10]` and skips byte 3.
On its non-skip path, `0x3be4b69` reads the pair pointer from capture `+8`,
then `0x3be4b6d` loads its first word into RCX and `0x3be4b70` loads its
second word into R8. The direct call at `0x3be4b7c` enters `0x3421980`.
The entry constructed above supplies byte 2, so it takes this non-skip path.

Checkpoint loop `0x4875ba0` saves capture `+8` in RBX (`0x4875c4f`).
At each iteration, `0x4875cad` loads `[rbx]` into RCX and `0x4875cb0`
loads `[rbx+8]` into R8, then calls `0x42c70c0` at `0x4875cc8`.
The loop does not increment or replace RBX. Its constructed range selects
the two inline bundle bytes 0 and 1. Both calls consequently use the same
pair; this is a single shared override, rather than an array indexed by bundle.
The retained entire loop includes its iteration and failure/cleanup edges.

Both wrappers immediately preserve R8 in R14 and RCX in R15, before lookup
and validation. At `0x3421a56` and `0x42c71b1`, respectively, they test
`r15b & 1`, load default 2 or 16 into EDI, and `cmovne rdi,r14`.
Therefore, when option creation is reached, the selected GiB count is:

```text
state:      incoming RSI at 0x37d4e30 has bit 0 clear ? 2  : incoming RDX
checkpoint: incoming RSI at 0x459a4c0 has bit 0 clear ? 16 : incoming RDX
```

This is a bit test, not `first_word != 0`; e.g. a hypothetical first word
2 would still select the default. No claim is made that noncanonical Rust
discriminants are valid source-language inputs. The wrapper still has its
lookup, validation and allocation failure paths; the checkpoint wrapper also
has a sentinel return before option creation. No cache is promised to be
created merely because the pair is present.

The pointer/word transfers and choice are observations. Calling this pair an
`Option<u64>` and the words its tag/payload is an ABI interpretation consistent
with the use; no Rust source type or command-line option identity was recovered.

## Implementation and comparison

Not implemented or measured: no Rust component, build flags, Cargo.lock,
target execution, behavioral differential run, relocation-normalized code
comparison or helper closure. No normalization masks are used. This packet
does not add a compiled byte window or change any progress gate.

## Results and limitations

- Before: two downstream wrappers had known cache-selection arithmetic, but
  the pair's provenance through their collectors was unresolved.
- After: six LLVM-confirmed direct calls connect two entry-register pairs
  through capture construction/copy and per-bundle loads to the selectors.
  Eight complete FDE ranges and 17 byte pins are retained.
- All 23 targeted corruptions were rejected: one mutation in each of the 17
  provenance byte spans, plus one mutation of each of six call displacements.
  These checks deliberately bypass the full digest to exercise the local
  evidence checks. They validate evidence admission, not execution equivalence.
- Concrete entry RSI/RDX values remain unknown. It would be incorrect to
  conclude either path always uses 2/16 GiB, or always enables an override.
- The six listed calls are validated paths, not a whole-program caller census.
  No source ownership is inferred solely from FDEs or earlier labels.
- Failure paths, filesystem effects, aliases inside transitive pre-collector
  helpers and full RocksDB behavior remain outside this static packet.

Next question: which callers of `0x37d4e30` and `0x459a4c0` supply their
incoming RSI/RDX, and are those values tied to a validated configuration field?
