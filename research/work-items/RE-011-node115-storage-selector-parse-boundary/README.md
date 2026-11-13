# Storage RPC selector parsing and the current-context boundary

Advances HL115-096 / RE-011 by recovering the public number-string parser and
tracing its actual positional `BlockId` carrier to the storage callback. The
selected synchronous storage path builds a read tuple from its current context,
address and storage key; it does **not** establish a join to asynchronous
selector helper `0x2a0bf50`.

Target node115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Only static original-ELF inspection and source-owned Rust tests were used;
no target execution or emulation. The eight retained windows contain 10,347
bytes / 2,222 instructions, with 367 facts and 367 negative overlays.

## Prior scope and what this adds

[#2171](https://github.com/lalalune/hyperliquid-source/pull/2171),
`RE-011-storage-read-115`, establishes the callback at `0x2d018b0`, object
parser/visitor and storage read chain. It explicitly leaves the shared
positional block parser opaque. It also notes that the tuple constructed by
`0x2a1f3b0` does not copy R8, without assigning complete selector behavior.
The `RE-001-node115-evm-block-selector-lowering` packet maps the raw modes of
`0x2a0bf50` and leaves public names unresolved.

This packet recovers the missing literal-to-number parser, the real positional
third-parameter chain and its result movement, and ties that argument to the
selected current-context tuple. Existing storage-key and database read logic
are credited, not reimplemented. It neither assigns the asynchronous helper
to the storage RPC by numeric-tag resemblance nor claims a snapshot-height
contract absent evidence.

## Public number text

`0x143e0e0` receives decoded string content, copies it through `0x141cc40`, and
compares length and literal bytes. Successful result tag 8 carries a u64 mode
at +8; numeric mode 5 also carries a u64 value at +0x10.

| String | Raw mode |
| --- | --- |
| `latest` | 0 |
| `finalized` | 1 |
| `safe` | 2 |
| `earliest` | 3 |
| `pending` | 4 |
| lowercase-prefix `0x` hexadecimal number | 5 |

The named variants do not give the second result word a semantic value.
Unrecognized names or absence of lowercase `0x` produce outer tag 7. Numeric
errors use outer tag 5 with byte 0 for empty digits, 1 for invalid digits and
2 for overflow. A single leading `+` is allowed before at least one hex digit;
upper/lowercase hex digits and arbitrarily many leading zeroes are accepted.
`0x+`, negative values, separators and whitespace in the digit span fail.
The long-input path checks overflow and invalid-digit classification in the
observed order: an invalid character at the first overflow opportunity gives
invalid-digit, whereas an earlier valid overflowing digit has already failed.

`src/node115-block-number-text` implements this function over an already decoded
Rust string. It does not parse JSON, silently change the API to a canonical
quantity grammar, or read unused native payload bytes. Tests exercise literal
names, case sensitivity, 12,291 numeric spellings, u64 boundaries, leading
zeroes, optional plus and error precedence in debug and release builds.

## Actual positional storage carrier

The direct string arm of `0x26e32c0` treats length **66** specially: it calls
hash parser `0x2a31740`. Otherwise it calls `0x143e0e0` through relocation
`0x64dfae0` at `0x26e3951`. On numeric/name success, `0x26e3962..3997` and
`0x26e3e69..3edb` construct a `BlockId` with outer byte 1, raw mode at +8 and
numeric payload at +0x10. Hash/object/canonical parsing is retained as context
but not reconstructed here. In particular a length-66 string accepted by the
standalone number parser need not take that path in `BlockId`.

The actual callback chain for the third positional argument is:

```text
0x2d018b0 at 0x2d01f2f
  -> 0x2d0f2e0 at 0x2d0f3b4
  -> 0x1d6c2c0 at 0x1d6c347
  -> 0x22a8cf0 at 0x22a8dd8
  -> 0x26e32c0 at 0x26e3951
  -> 0x143e0e0 through GOT 0x64dfae0
```

`0x22a8cf0` represents `null` as byte 2, maps a BlockId error to byte 3, and
copies successful BlockId fields unchanged. The positional wrapper preserves
that result; `0x2d0f2e0` writes its outer tag 3 and the optional BlockId at +8.
The storage callback copies the value from stack +0x28 into its 40-byte local
at +0x110, or sets byte 2 for the parser's no-argument result. At
`0x2d01fcb..1fd6` it passes a pointer to that local in **R8** to `0x2a1f3b0`,
alongside separately prepared address and index arguments.

This establishes a real accepted-parameter handoff. It does not prove that
all decoded variants pass every earlier parameter guard, and does not model
JSON errors, allocation failures or unwind behavior.

## Selected current-context projection

The complete retained `0x2a1f3b0` FDE contains no explicit reference to R8 or its
subregisters. More concretely, its tuple construction is:

- `P = [context + 0x3d8]`, tuple[0] = P + 0x10;
- tuple[1] = the address pointer received in RDX;
- tuple[2] = the storage-key pointer received in RCX;
- tuple[3] = the local `eth_getStorageAt` label object.

For **P+0x160 == 0** the inspected branch directly calls `0x2a39b80` with that
tuple at `0x2a1f49d`. The callee takes its context C from tuple[0], acquires the
reader lock at C+0x6a8, and loads the database-holder pointer at C+0xb00. Its
selected untimed arm copies the address, converts either key representation,
and passes **holder+0x1c78**, address and 32-byte key to the relocated
`0x43c89a0` reader at `0x2a39e2e`. The explicit tuple and read arguments do not
contain the parsed BlockId. The existing predecessor owns the lower read
algorithm and missing-key behavior.

This is a static argument/dataflow result under valid object identity, ordinary
callee ABI behavior, successful lock acquisition and normal helper returns.
It is **not** a general noninterference theorem about all helpers, ambient
state, concurrent mutations or telemetry. It does not prove that the current
holder corresponds to the public meaning of `latest`, `pending`, a particular
height, or an archival snapshot. Nothing here demonstrates the storage callback
calling `0x2a0bf50`; a source integration must not invent that join.

## Reproduction and remaining work

```sh
python3 research/work-items/RE-011-node115-storage-selector-parse-boundary/verify.py --target /path/to/hl-node
cargo test --manifest-path src/node115-block-number-text/Cargo.toml
cargo test --release --manifest-path src/node115-block-number-text/Cargo.toml
cargo clippy --manifest-path src/node115-block-number-text/Cargo.toml --all-targets -- -D warnings
```

The verifier authenticates the target, FDE/instruction windows, parser and
reader relocations, actual caller arguments and dispatch bytes. Negative
controls bypass digest/window checks and must fail the recorded facts. They
validate evidence anchors; they do not execute the recovered program.

Remaining: full JSON/hash/canonical grammar, all registration paths, actual
snapshot-height ownership and coherence, the stateful archived selector path,
and behavior across every lock/cleanup/failure branch. This is a partial
backlog contribution, not completion of HL115-096 or any component gate.
