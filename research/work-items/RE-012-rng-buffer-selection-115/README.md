# RE-012: implement node #115 buffered draw/reseed policy transitions

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`, foundation utility under
RE-012 startup/helper scope. Independently authored MIT Rust/scripts/docs;
captured disassembly retains original rights. No inferred unlicensed source
copied. All component gates and byte-comparison counts remain unchanged.

## Gap and delivered scope

Earlier static PR #2792 recovered the generated-name function and observed its
TLS u32 draw/refill boundaries, but supplied no Rust state kernel and left
reseed semantics open. This contribution follows the complete reseed helper,
proves that its selected CPU seed-initialization paths have the same result,
and implements the closed scheduling and persistent-state transitions in
`src/node115-rng-buffer-selection` with a real dependency-free Cargo graph.
This is additional implementation and reseed-state evidence, not a duplicate
claim for the earlier static name formatting or a complete RNG implementation.

A buffered request can return a stored word immediately. A depleted request
selects fast refill or entropy acquisition. Entropy failure normally continues
with the old key, while success installs seed32 plus sixteen zero bytes.
Both reseed arms write the observed epoch before checked budget subtraction.
Overflow can therefore follow an already installed key/epoch without committing
a new remaining budget. Explicit pending requests preserve these boundaries;
no entropy callback, generator stub or fake success is supplied.

## Exact static evidence and observed layouts

Four full FDEs are retained: generated-name context
`0x1501360..0x15016f0` (912 bytes), reseed helper
`0x5bb9850..0x5bb99ad` (349 bytes), seed-state initializer
`0x5bb99e0..0x5bb9a51` (113 bytes), and external block-refill context
`0x5bba800..0x5bbb030` (2,096 bytes). Total 3,470 bytes/768 instructions.
Only established policy/seed initialization is implemented; retaining a full
refill context does not establish that generator's algorithm. These are not
registered compiled equality windows or a whole-component denominator.

`records.json` preserves original instruction bytes, full FDE/CIE records,
actual calls/branches and relocation writers. GNU/LLVM/Capstone agree on all
instruction partitions; native readelf independently checks exact extents.
The original contexts and shared dependency bytes receive no new first-party
byte credit. Seventeen real instruction/data anchors reject individual byte
corruption below whole-image hashing; wrong/truncated captures reject separately.

Observed fields relative to the retained object: buffer u32[64] at +0x10,
cursor qword at +0x110, 48-byte key/counter state at +0x120, base budget at
+0x150, remaining budget at +0x158, observed epoch-like word at +0x160.
Names are inferred roles, not original Rust types or a `repr(C)` claim.
The smaller reseed helper receives object+0x120, so its +0x30/+0x38/+0x40
refer to the last three policy fields. The Rust `State` stores only those
logical fields, the complete buffer and key state; TLS/reference headers and
native alignment are outside this API.

At `0x150139d..0x1501409`, cursor<64 reads buffer[cursor] then increments the
cursor. A depleted cursor uses remaining>0 and the sign bit of the wrapping
subtraction `(stored_epoch - current_global)` to select fast refill. This is
specifically the native `js` condition, **not** an overflow-correct signed
ordering test. The actual global is loaded from `0x64fff30`; its semantic type
and concurrent updates are unresolved. The Rust caller supplies that boundary
value explicitly; it does not read TLS, globals or the OS.

Fast refill subtracts 256 from the positive remaining budget and calls
`0x64e0980 -> 0x5bba800` with native argument ESI=6. This positive-input
subtraction cannot overflow i64. The other arm calls
`0x64e0988 -> 0x5bb9850`, passing the current global value as its third
argument. Only after the refill returns normally does the caller select
cursor0, read its first u32, and store cursor1. No pre-call cursor reset or
rollback is invented.

## Reseed transitions and seed initializer closure

At `0x5bb9874`, the helper requests exactly32 bytes through the real relocated
slot `0x64e22f8 -> 0x17718f0`; zero return status means success. A nonzero
status allocates a four-byte error box and destroys it. If that cleanup returns
normally, the helper retains the old 48-byte key state and continues to refill;
it does not return an entropy error to the buffered caller. Allocation failure
or panic during cleanup is an external failure boundary excluded by the Rust
`EntropyOutcome::Unavailable` normal-return contract.

On success, the scalar feature arm copies seed32 and sets the next16 bytes to
zero. The selected alternate initializer at `0x5bb99e0` receives nonce length8
and the eight actual zero bytes at `0x459348`. Its full stores copy seed32,
write zero at +0x20 and +0x24, and load the two nonce dwords into +0x28/+0x2c.
Thus both selected CPU paths install the same 48 bytes. General nonce lengths
and other users of this initializer are not implemented. This is a concrete
seed-state installation, rather than an opaque install-key callback.

Both entropy outcomes load the **base** budget. They write the current epoch
at `0x5bb98b2`/`0x5bb9990` before checked `base-256`. Success has already
installed its new key before that epoch store. If subtraction overflows,
`0x5bb99a0` reaches the failure helper without writing the new remaining
budget or calling refill. Prior key/epoch writes remain. Normal arithmetic
stores the new remaining budget, then calls the same refill target with
argument6. A rollback implementation or subtraction from the old remaining
budget would contradict these ordered stores.

## Safe staged API and external boundaries

`begin(&mut State, epoch)` returns `Step::Word`, `EntropyRequest` or
`RefillRequest`. Pending requests own the unique mutable state borrow and
cannot be cloned or resumed twice. `EntropyRequest::resume` consumes an
explicit caller-provided seed or the normal-cleanup failure boundary and
performs the real closed key/epoch/budget stores. `BudgetOverflow` represents
the captured arithmetic failure boundary; native panic payloads and ABI are
not reproduced.

`RefillRequest::complete` requires a caller-supplied `RefillOutput` containing
the full post-refill key48 and buffer64. It retains both, returns buffer[0]
and leaves cursor1. It neither computes those words nor pretends a generator
ran. A caller who drops a pending request gets no output and no rollback.
Native execution between callbacks, concurrent global changes, entropy-source
behavior and refill cryptographic correctness remain open. The requirement
that supplied state/buffer/boundary results belong together is an explicit
integration precondition, not a synthetic fake implementation. The provider
contract also preserves cursor/base/remaining/epoch across the external refill
call; the retained default body supports bounded key/buffer writes, while full
alternate CPU-tail write-effect closure remains unproved here. `complete` is
conditional on that provider contract, not evidence that every native refill
arm already satisfies it.

## Independent qualification and actual results

`oracle.py` specifies the branch relation and exact intermediate/final policy
state using unbounded integer arithmetic, a modular subtraction-sign test and
explicit external boundary values. It does not step target instructions.
`freeze.json` records its hashes while the new Rust directory did not exist.
14,128 frozen rows cover cursor0/1/62/63/64/65/u64MAX, every cursor0..66 in
additional witnesses, positive/zero/negative budgets, i64 minimum and checked
subtraction boundaries, half-range/wrapping epoch differences, seed success
and failure, and varied key/seed patterns. Synthetic seed/refill arrays are
arbitrary caller-supplied boundary fixtures, never represented as captured RNG
output or proof of randomness.

Opt-level0 and3 actual compiled Rust both match every frozen status/state row.
The probe additionally checks retention of every supplied refill word and a
second buffered draw from a cloned post-refill state. Those buffer/followup
assertions were added after the first Rust draft and are not falsely described
as pre-production frozen expectations. Six actual compiled mutants terminate
normally and are detected: cursor63 threshold, signed ordering replacing
subtraction-sign, fast budget255, nonzero seed tail, epoch rollback on overflow,
and subtracting remaining rather than base budget. `qualification.json`
retains first divergent witnesses, source/probe and expected-output hashes.

The dependency-free manifest/lockfile has no build hooks. Host Cargo build,
Linux/amd64 release rlib build, Clippy all-targets with denied warnings and
rustfmt check pass. Only newly authored Rust host probes are executed; Linux
build emits an rlib and does not link/run a target executable. Commands from
repository root, after sourcing `work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-rng-buffer-selection-115/verify.py
python3 -B research/work-items/RE-012-rng-buffer-selection-115/qualify.py --out work/rng-buffer-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-rng-buffer-selection/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-rng-buffer-selection/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-rng-buffer-selection/Cargo.toml
```

Tools: Python3.14.5, Capstone5.0.7, GNU binutils2.45, LLVM23.1.4, Rust1.95.0.
This is conditional logical state reconstruction, not captured differential
execution, native ABI, instruction equivalence, complete RNG, OS/TLS behavior
or whole-node integration. No acceptance gate or byte-equivalence count moves.
Next: establish the licensed refill primitive and CPU-feature selection before
joining this policy to a real compatible generator and entropy provider.
