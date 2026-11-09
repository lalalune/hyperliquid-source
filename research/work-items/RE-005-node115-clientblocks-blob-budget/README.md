# RE-005: #115 ClientBlocks attachment-blob budget and cursor

The [ClientBlocks grammar packet](../RE-001-node115-client-block-success-grammar/README.md) identifies an attachment's hash followed by a length-prefixed raw byte blob, and notes that `0x5824b60` charges the length and checks full payload availability. It leaves general budget and malformed-input ordering open. This packet maps the selected blob helper's charge, remaining-length check, copy and cursor writes. It is distinct from the [open outer-vector budget PR #5061](https://github.com/lalalune/hyperliquid-source/pull/5061), which handles 16-byte vector elements. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses; target code is not executed or emulated.

## Selected call and budget gate

After the selected hash-reader path, `0x4e04e90` passes its saved state pointer and calls blob helper `0x5824b60` at `0x4e04ef4`. The blob helper first calls length reader `0x5821250`. If that reader does not return byte tag `0x12`, the helper propagates its selected result fields without entering the following blob-specific steps. The grammar packet owns the hash and general structural meaning; this packet authenticates the selected call and analyzes the subsequent ordering.

After a successful length-reader return, let `N` be its qword result, `C` the then-current state qword at `+0x20`, `L` the limit at `+8`, `P` the cursor at `+0x10`, and `R` the remaining byte count at `+0x18`. Count-reader consumption and charges may already have changed the state; they are not included in the analysis before this point. When the state qword at `+0` is zero, the blob helper skips its own charge. Otherwise it computes `C + N`. Carry selects byte tag 2 before storing the sum; without carry, the sum is stored at state `+0x20` **before** comparison with `L`. A sum above `L` returns tag 2 with the new charge stored, while equality passes this gate.

After that gate the helper computes `R - N`. If subtraction borrows, it returns byte tag 1 without its own cursor or remaining-count stores. The charge may already have been committed: for example, `C=5`, `N=4`, `L=9`, `R=3` stores 9 and then takes the short-input result. With `L=8` it stores 9 and stops at tag 2 before checking `R`. These examples describe local steps after the length reader, not complete request accounting or runtime tests.

## Copy and selected return

When the length and availability gates pass and allocation/copy calls return normally, the helper obtains `N` bytes of storage for nonzero `N`; `N=0` selects raw pointer value 1. A high-bit-set nonzero `N` goes to a separate failure call; its behavior is not reconstructed. The helper calls through `0x64df508`, whose dynamic relocation names `memcpy`, with `(destination, P, N)`. Only after that call does it store cursor `P+N` and remaining `R-N` to the state, then write tag `0x12` and raw output qwords `(N, destination, N)` at offsets `+8`, `+0x10`, `+0x18`. The selected zero-length path also reaches the copy call with length zero, so any zero-length pointer validity and dynamic `memcpy` contract are explicit premises.

The complete blob FDE contains no register-indirect call; the supplied byte callback is not invoked by this optimized path, as already observed by the grammar packet. We do not assert what the separately called length reader accepts, what allocation or `memcpy` does under failures or interposition, or that the input buffer and output storage may alias. The parent copies the blob error result on a non-`0x12` return; no final RPC or transport error is claimed.

## Evidence and limitations

`instructions.tsv` records the complete blob, attachment and length-reader FDEs. `verify.py` authenticates the target digest, three indexed FDE bounds/body hashes, 223 instruction spans, 46 pins, six targets, two relocations and the `memcpy` dynamic symbol; it checks the no-register-call observation, five arithmetic ordering examples and nine rejected mutations. These are static checks and arithmetic consequences, not target execution or emulation. Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-005-node115-clientblocks-blob-budget/verify.py` using Capstone.

Other nested ClientBlocks charges, length-reader failure effects, allocation and unwind behavior, arbitrary pointer aliasing, dynamic execution, final network framing and cross-version equivalence remain open. No component gate is requested.
