# Startup name → joined bytes → metadata → UTF-8 admission

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE and instruction data-flow only; no captured execution or emulation.

## Gap and prior evidence

This closes a supplied-input boundary in the startup discovery work for #3927. #4322 / `src/node115-startup-admission` reconstructs admission given already-joined path bytes and metadata results, while explicitly leaving actual path construction to the caller. #7052 separately establishes ordering of admitted strings; its source likewise preserves that supplied-input premise. Neither establishes how the mapper constructs the byte string or proves that metadata lookup and UTF-8 conversion receive the same constructed buffer.

`RE-002-node115-cgroup-v1-integer` names `0x5c89400` at a file-reader call boundary but leaves joining opaque; `RE-017-abci-prune-path-115` records mapper context without reconstructing that helper. Those are prior attempts, not new claims here.

The new source crate reconstructs the selected helper's logical successful join and composes it with the unchanged admission crate. It accepts a directory byte prefix and successful C-string entry names, plus a supplied metadata callback. This closes the path-construction and input-order boundary while keeping filesystem behavior and metadata results explicit dependencies.

## Caller input and byte identity

At `0x150bad0`, the successful enumeration arm obtains the directory byte pointer/length from the shared entry object's +0x18/+0x20 (`0x150bb0c`/`0x150bb10`). The entry name pointer is the previously loaded RCX (`0x150bae7`). Its stored name length becomes R8 and is decremented once at `0x150bb19`, excluding the terminating NUL before calling `0x5c89400` through relocation `0x64e0b58`. This is a valid C-string input contract, not permission to discard an arbitrary last byte. The source therefore represents successful names as `&CStr` and uses `to_bytes()`.

The constructor writes an owned capacity/pointer/length triple to stack+0x30. Its pointer and logical length are loaded into R14/R15 at `0x150bb27`/`0x150bb2c`. The mapper passes those exact registers to metadata helper `0x5c9c810` at `0x150bb3c`, then to UTF-8 helper `0x16815e0` at `0x150bba7`. No second join or filename extraction intervenes. The UTF-8 helper's success arm returns the original pointer and length unchanged (`0x16817a7`/`0x16817ab`), and the mapper copies those bytes into its admitted owned result.

Metadata is looked up **before** UTF-8 validity is decided, including when the final joined bytes are invalid UTF-8. A metadata failure follows the existing directory-flag-false contract; a failed enumeration entry skips construction and metadata altogether. The source callback receives the joined bytes before the unchanged admission crate applies UTF-8/view filtering. The crate itself performs no filesystem access; the callback supplies the explicitly modeled metadata result.

## Selected constructor contract

`0x5c89400` first copies the base bytes into owned storage. It then produces this logical result:

1. A nonempty child beginning with byte `/` discards the logical base length and appends the child exactly.
2. Otherwise, a nonempty base whose final byte is not `/` gets one `/` appended. This also happens when the child is empty.
3. Append the child bytes exactly; an empty base requires no separator.

The branch at `0x5c8948f` inspects only the first child byte. The branch at `0x5c89456` inspects only the last base byte. The final append is a checked `memcpy` binding with the original child pointer/length. There is no component parsing, Unicode conversion, slash collapse, dot/dot-dot resolution, backslash interpretation, or numeric-name conversion in this helper.

| Base | Child excluding terminator | Result |
| --- | --- | --- |
| empty | empty | empty |
| `root` | empty | `root/` |
| `root/` | `one` | `root/one` |
| `root//` | `.././x` | `root//.././x` |
| `root` | `/absolute//x` | `/absolute//x` |
| invalid UTF-8 base | `/valid` | `/valid`, which can pass UTF-8 admission |

Validation after joining matters: rejecting an invalid base before noticing an absolute child would disagree with the mapper. Conversely, invalid relative-name bytes are joined and sent to metadata before UTF-8 admission rejects them.

`0x5c7f850` handles reserve growth, checked required length, and pointer/capacity replacement via `0x5c8b9f0`. This packet records those boundaries but assumes ordinary successful allocation and preservation of existing initialized bytes across reserve. It does not reconstruct the allocator implementation. The source may skip the native initial base copy for an absolute child because only the successful logical bytes are modeled; allocation counts, failure timing, aborts and native ownership layout are explicitly excluded.

## Validation

```sh
python3 research/work-items/RE-012-node115-startup-path-join/verify.py --target artifacts/node/115/hl-node
cargo test --manifest-path src/node115-startup-path-join/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools 0.32 for the verifier. Five FDE transcripts retain 505 instructions and 59 selected witnesses, with three function relocations and one memcpy import binding. Eight negative controls reject target changes, retaining the terminator, passing a different metadata/UTF-8 buffer, using the wrong separator, retaining the base for an absolute child, omitting the empty-child trailing separator, and copying the wrong child length.

Source fixtures cover exact bytes, separator and absolute/relative boundaries, C-string NUL exclusion, invalid-UTF-8 callback order, absolute replacement of an invalid base, failed enumeration and outer errors, and nested non-directory admission. These are source reconstruction fixtures backed by static evidence, not captured filesystem observations.

No claim is made about live directory identity, enumeration order, symlinks, stat-system-call policy, native allocation failures, subsequent sorting/tree construction, checkpoint selection, or checkpoint validity. Existing component completion gates remain unchanged.
