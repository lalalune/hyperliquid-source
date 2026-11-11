# Node 115 stored-word accepted-value decoder

Task **RE-001**, partial EVM/storage evidence for issue **#3918**, also relevant
to the `eth_getStorageAt` path tracked by **#3922**. Both issues remain open;
no component gate changes.

The existing [storage-read packet](../RE-011-storage-read-115/README.md) binds
the backend read and the empty-value failure but leaves the complete nonempty
value format unresolved. This contribution reconstructs the accepted byte
language of that actual value reader and supplies a dependency-free Rust
decoder. It adds no guessed key prefix, database implementation or RPC handler.

## Target and method

| Item | Identity |
| --- | --- |
| Artifact | `artifacts/node/115/hl-node`, 105,896,032 bytes |
| SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| Base | `0781ce04826eeefd89fe336cb8ea073be0c1de30` |
| Coordinates | ELF virtual addresses and enclosing `.eh_frame` FDEs |
| Static tooling | Python 3.14.7, Capstone 5.0.7 |
| Owned-source checks | rustc/cargo 1.95.0, offline (initial author checks used 1.93.1) |

`records.json` retains **23 windows / 5,951 bytes / 1,452 instructions**, plus
**489 facts** including the complete 256-entry marker jump table, all 17 typed
rejection visitors, the UTF-8 width table and the selected reader's actual
callers and result writes. The verifier checks the complete artifact digest,
FDE-relative instruction boundaries, retained bytes/rows, direct calls, data and
relocation targets. **35 corruption controls** are independently rejected by
semantic fact checks with the global digest/window checks bypassed. No captured
instruction was executed or emulated.

## Complete accepted language at this entry point

The entry point is a *fresh* reader created by `0x3d48180`, with no cached marker,
depth 32 and the byte-visitor argument set to 1. It is not the general decoder's
arbitrary internal-state interface.

| MessagePack header | Accepted payload | Successful consumed length |
| --- | --- | ---: |
| `c4 20` (bin8) | any 32 bytes | 34 |
| `c5 00 20` (bin16) | any 32 bytes | 35 |
| `c6 00 00 00 20` (bin32) | any 32 bytes | 37 |
| `d9 20` (str8) | exactly 32 bytes **invalid as UTF-8** | 34 |
| `da 00 20` (str16) | exactly 32 bytes **invalid as UTF-8** | 35 |
| `db 00 00 00 20` (str32) | exactly 32 bytes **invalid as UTF-8** | 37 |

All other inputs are rejected: empty/truncated inputs, other lengths, valid
UTF-8 strings, fixstr (whose maximum length is 31), numbers, booleans, nil,
reserved markers, maps, arrays and extensions. Nonminimal length-header forms
are accepted. Bytes after the first successful value are left unconsumed and
do not cause rejection by this wrapper.

The 32 payload bytes denote a big-endian 256-bit word. The selected output
contains four `u64` limbs in least-significant-first order. For payload bytes
`00 01 ... 1f`, the limbs are:

```text
[0x18191a1b1c1d1e1f, 0x1011121314151617,
 0x08090a0b0c0d0e0f, 0x0001020304050607]
```

The invalid-UTF-8 string fallback is observed native behavior, not a general
recommendation for MessagePack decoders. A valid ASCII string of 32 bytes is
rejected; a string of the same size containing an invalid byte such as `ff`
reaches the byte conversion.

## Native chain and branch evidence

1. `0x3d48700`'s previously mapped present-value arm gets the backend byte slice
   through relocation `0x64e61b0 → 0x5d35050`, then passes the actual pointer and
   length into `0x3d48180` at `0x3d487a8`. Database presence/error semantics and
   runtime key-prefix provenance remain credited to, and bounded by, prior work.
2. `0x3d48197–0x3d481d1` initializes a fresh reader and calls `0x3151e90` with
   byte-visitor selection 1. The successful wrapper copies all four limbs,
   publishes tag 0, and returns without testing the reader's remaining length.
   Its caller increments that success tag to the present-result tag 1.
3. `0x3151e9f–0x3151f25` consumes the initial marker. Fixed integers, maps,
   arrays and strings have explicit prefix tests. The remaining marker table
   is based at `0x6b0dc0`. Its bin8/bin16/bin32 entries reach `0x3152172`,
   `0x31520bd`, and `0x315209e`; its str8/str16/str32 entries reach
   `0x31521f7`, `0x31521c2`, and `0x3152212`.
4. The binary paths read unsigned 1/2/4-byte big-endian lengths, check that the
   payload fits, advance the cursor and preserve the suffix length. The true
   byte-visitor arm calls `0x43ca520`, which requires exactly 32 bytes and loads
   big-endian words from offsets 24, 16, 8 and 0 into output limbs 0 through 3.
5. String paths also check/consume the announced payload, then validate UTF-8
   through `0x64dfca8 → 0x16815e0`. The validator's success result is tag 0;
   its invalid/truncated-sequence result is tag 1. The reader tests that tag
   at `0x3152383`: valid strings branch to `0x431eef0`, which always returns a
   type error on normal return. Invalid UTF-8 takes the inline exact-32 gate
   and the same reversed big-endian word loads. The validator's lead-byte
   table, continuation checks, overlong boundaries, surrogate exclusion and
   maximum-code-point boundary are retained, rather than inferred from its name.
6. Scalar marker dispatch is `0x64e2b48 → 0x33cae80`. The integer, float,
   boolean and nil visitors, and the array/map/extension visitors, each preserve
   the result pointer, pass `result+8` to the error formatter, explicitly write
   outer tag 1, and return. Their full FDE windows have no conditional branches.
   This closes the rejection alternatives; a complete accepted grammar is not
   inferred from observing only the binary success case.

The 17 rejection visitors are `0x4319410`, `0x4318960`, `0x431f620`,
`0x431c2f0`, `0x431d420`, `0x431fce0`, `0x43203c0`, `0x431b740`,
`0x431a500`, `0x431ad00`, `0x43162e0`, `0x4316730`, `0x431eef0`,
`0x431e220`, `0x431e380`, `0x431de90`, and `0x4317f30`. Allocated error
formatting, allocator failures and abnormal unwinding remain outside the
owned-source contract.

## Source and validation

`src/node115-storage-value-decode` is `no_std`, forbids unsafe code and has no
external dependencies. Its `decode` returns the four limbs and successful
consumed length. `InvalidValue` is one local rejection marker; it does not
pretend to reproduce native diagnostic objects, exact failure cursor movement,
or exception behavior. Rust's `core::str::from_utf8` provides the standard UTF-8
predicate whose selected native implementation is statically bound above.

Three tests cover every initial marker, all truncation points of valid binary
forms, wrong lengths, endian/limb order, trailing data, valid multi-byte strings,
and **4,716 cross-language fixtures**. The reference uses Python `struct` for
header lengths, Python's independent strict UTF-8 codec, and one arbitrary-
precision big-endian integer before extracting limbs. It does not import or
run the Rust code, and it is not a native-runtime oracle. The fixture dimension
is 6 header forms × (3 byte positions × 256 byte values + 18 UTF-8 boundary
sequences). The results are **3,543 accepted / 1,173 rejected**.

| Changed reference assumption | Differing cases / 4,716 |
| --- | ---: |
| Reject every string form | 1,185 |
| Accept valid UTF-8 strings | 1,173 |
| Reverse the UTF-8 decision | 2,358 |
| Reverse output limb order | 3,534 |
| Require end-of-input | 3,543 |

`reference.py` checks the retained fixture and summary byte-for-byte; `--write`
regenerates them. The static mutation set includes a changed binary-marker
target, wrong length/endian/limb fields, reversed UTF-8 branch, substituted UTF-8
callee, Unicode boundary corruption, all 17 error visitors changed to success,
and incorrect fresh-reader options.

From the repository root, with the pinned artifact and recorded static tooling:

```sh
python3 research/work-items/RE-001-node115-storage-value-decode/verify.py
python3 research/work-items/RE-001-node115-storage-value-decode/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-storage-value-decode/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-storage-value-decode/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-storage-value-decode/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-storage-value-decode/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-001-node115-storage-value-decode/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

Final publication checks are recorded in the PR. Full unfiltered `make test`
is excluded because discovery includes captured-instruction emulation, which
is outside the authorized scope. No hosted-CI or full-node equivalence is claimed.

## Scope and overlap

This closes the selected fresh reader's accepted value format. It does not
establish a runtime prefix such as `Es`, database contents, durable storage,
all EVM methods, JSON request/response behavior or the general rmp-serde parser.
Safe slice validity and normal helper returns are premises; native allocation,
error text, ABI padding, diagnostic side effects and unwinding are unmodeled.

Current main, the open-PR inventory and targeted all-state searches for
`0x3151e90`, `0x43ca520` and storage-value decoding were checked. The existing
storage-read packet explicitly left this format open, and the existing storage
key builder only constructs keys. New database-open and transient-journal PRs
cover distinct paths. Metadata search can miss unindexed patch content; this is
not a claim that every historical diff was manually inspected.

Original implementation and interpretation: OpenAI `gpt-6-astra`,
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra`, `codex-desktop`. No unlicensed inferred source was copied.
