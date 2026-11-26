# Selected owned TCP frame to write progress

Partial RE-012 transport work on Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This connects a real framed allocation to the selected send slice and its
normal/error cleanup. It does not establish full transport, asynchronous ABI,
cancellation safety, remote delivery or peer identity.

## Prior work and new ownership relation

`RE-012-node115-tcp-prefix` established the five-byte header and frame
allocation in `0x2b7a290`. #2166 (`src/node115-write-progress`) owns the
prepared-slice scalar transition and one initial counter charge. #3159 owns
`0x5cdfc90` readiness and send boundaries. #3655/#3656 own separate nested
cleanup predicates, and RE-012-greeting-deadline-115 owns the chunk-local
deadline choice. None of these is reimplemented or credited as new here.

On the selected normal frame-construction route, `0x2b7a702` allocates payload
length plus five; `0x2b7a726` stores pointer P at owner+`0x88`. It writes the
big-endian u32 payload length and marker, copies payload into P+5, and stores
length at +`0x90`. The descriptor at +`0x98` is copied at `0x2b7a821..82d`
to +`0xb8` (P), +`0xc0` (remaining), +`0xc8` (4,000,000-byte cap).

At `0x2b7b22d..250` the selected chunk pointer is current +`0xb8`; its size
is `min(+0xc8,+0xc0)`. The remaining descriptor advances by that chunk size.
The chunk future stores the pointer at owner+`0xf8` and length at +`0x100`.
The copies at `0x2b7aaf8..ab6a` take +`0xf0` into stack+`0x260` and then
copy 0x170 bytes from stack+`0x180` to owner+`0x168`, mapping those two words
to owner+`0x250/+0x258`. The next copy chain at `0x2b7abcf..ae82` moves
them through stack+`0x110/+0x118` and stack+`0x1f0/+0x1f8`, then copies
0xd8 bytes from stack+`0x180` to owner+`0x168`, mapping the words to owner+`0x1e0/+0x1e8` (pointer/length). The sender
loads those words at `0x2b7af1c/23`, initializes its active pointer/remaining
at +`0x230/+0x238`, and calls `0x5cdfc90` at `0x2b7afda`. Thus, conditional
on the selected route, normal copies and no alias writes, the pointer is a
slice of P rather than merely a matching field layout.

On a selected positive successful write, the existing transition advances
+`0x230` by the returned count and subtracts that count from +`0x238`; result
2 writes nested state 3 and suspends. The selected ready-success and error
continuations release P at `0x2b7b35f..368` or `0x2b7b332..33b` respectively,
then visit the distinct original-payload cleanup. Pending follows the
suspension return rather than these normal cleanup paths. No claim about drop
of a cancelled future or every unwind path follows.

## Source and limits

`src/node115-owned-frame-send` builds an owned frame and passes each logical
chunk through unchanged `node115-write-progress::advance`; it uses the
existing chunk constant. Its `std::io::Write` interface is an offline adapter:
WouldBlock is mapped to pending, and other I/O errors to a terminal error, by
this API. This does not recover the native socket readiness, errno conversion,
timer, or future ABI. It accepts a caller-supplied compression marker and
already-selected payload; it does not implement compression. The API's terminal
repoll and allocation behavior are its own choices. Successful allocation,
normal helper/copy returns, valid object layouts, and no concurrent alias
mutation are premises. Native allocator failure, full cancellation/destructors,
interleavings, all error paths and scheduling remain open.

## Verification

`verify.py --target <pinned-ELF>` checks the full digest and enclosing FDE,
7 selected windows (292 instructions), 47 instruction facts and six
counterfactual witness controls. It reads but never executes the captured node.
Five Rust tests cover short writes followed by WouldBlock/resume without a
second charge, including a suspension in the second chunk, header bytes, frame sizes on both sides of the 4M boundary,
zero progress and partial-write error cleanup. These tests use an isolated
`Write` adapter; they are not target differential execution. Debug/release,
formatting and strict Clippy are checked separately. No full-scope component
gate is changed.
