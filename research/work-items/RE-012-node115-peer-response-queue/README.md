# Peers response to selected key queue

Partial RE-012/RE-005 for Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This joins the existing source-owned Peers frame and normalized-set decoder to
one selected downstream consumer. It does not claim authenticated identities,
network reachability, peer freshness, or complete startup.

## Native path and source boundary

The previously reconstructed #6461 decoder and `src/node115-peers-response-set`
produce a normalized set ordered by four key bytes and preserve only the last
wire row for an equal key. The `0x2e467ea` decoder invokes `0x2dd2980`; on its
selected success route `0x2e46815` writes raw result qword 4. In the selected
caller `0x2cc1120`, the request object's raw word is set to 1 at `0x2cc6321`,
and the poll `0x2cb1eb0` is called at `0x2cc6356`. The ordinary ready response
is gated by outer tag `0x44` at `0x2cc6417` and decoded qword 4 at `0x2cc6451`.
The path handles other outcomes separately. This is a static selected path;
it is not a claim that every request reaches it.

The returned small-set representation is made into a two-span iterator at
`0x2cc6902..0x2cc69f8`; `0x5acbae0` at `0x2cc6a03` also has a tree iterator
route. Flat rows have a 24-byte stride: the flat loops test row byte `+0x10`
for nonzero (`0x5acbbaf`/`0x5acbd05`), and the generic path tests the value
byte returned by `0x5135900` plus 8 for equality with 1 (`0x5acbb6d` and
`0x5acbcd1`). The tree iterator forms the key address as node `+0xb8+4*i`
and the corresponding value address as node `+16*i` (`0x5135ad1..0x5135adf`).
For each selected row, `0x5acbbe4`/`0x5acbd3f` loads the key dword and the
vector append stores it at `0x5acbd6b`. The tree traversal and #6461's
normalized order are credited prerequisites. On valid decoded booleans both
predicates agree: #2795's element decoder rejects bytes greater than 1 at
`0x5aaa581`. Invalid in-memory values are outside this contract.

At `0x2cc6a25..0x2cc6a3c`, the caller passes the resulting u32 slice to
`0x2486360` on its supplied destination. On its selected normal path the
helper appends the existing destination tail before wrapping, copies elements
in order, and updates destination length; the source keeps the four bytes of
each key rather than assigning a host-endian address meaning. The new
`src/node115-peer-queue` crate reuses the prior decoder and implements the
logical selection and append using `VecDeque<[u8;4]>`; it does not duplicate
native container allocation or claim to reproduce its layout. The convenience
`decode_and_append` entry point changes its supplied queue only after its own
decoder returns success; this is a source API property, not a claim about all
native error paths.

Valid decoded rows, stable set traversal, successful allocations and helper
returns, and a valid initialized destination are premises. Capacity growth,
allocation failure, unwind, concurrent mutation, later queue consumption and
native future/error ABIs are not implemented. In particular no meaning is
assigned to the flag or four-byte key beyond their observed use here. No
component completion gate is changed.

## Verification

`verify.py --target <pinned-ELF>` checks the complete target digest, eight
selected byte-window digests and 35 exact decoded instruction pins. Single-byte
controls demonstrate that those individual pins reject changed bytes; they do
not independently prove the interpretation. It reads the captured target but
never executes or emulates it. Use Python with Capstone and pyelftools.

`cargo test --offline --manifest-path src/node115-peer-queue/Cargo.toml` and
`--release` run four tests. In addition to explicit ordered/duplicate/false
flag cases and a wrapped queue with two successive responses, one test reads #6461's independently authored frozen wire corpus:
195 successful frames and 34 error cases, including small/tree boundaries,
compressed frames and repeated keys. Its expectations share the prior corpus's
interpretation, so this is integration validation, not an independent native
runtime oracle. Formatting and strict Clippy are also checked.
