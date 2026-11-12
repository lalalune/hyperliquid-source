# Execution-state producer: history membership and result layout

This advances **HL115-022** on node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The new scope is producer `0x2af6580`: its two leading history collections, their flat-ring selection rules, and the source of the remaining result lanes. It does not reconstruct all nested payloads or assign protocol names to unknown fields.

The existing `RE-008-node115-execution-projection` packet studies the downstream selector at `0x2af7150`, including its call to this producer at `0x2af7435`, but leaves the producer opaque. This packet supplies concrete membership and ordering constraints for that consumer. Earlier comparator and publication studies remain credited; they do not establish which input rows this producer actually includes.

## Native inputs and result

The ABI is output in `rdi`, a wrapper pointer in `rsi`, bounds in `rdx`, and an optional 20-byte selector in `rcx`. Let `S=*[rsi]`. Only bit 0 of the first bounds word activates cutoffs; the two cutoff values then come from bounds+8 and bounds+0x10. The fourth argument's selector is active only when its first byte equals 1.

| Result offset | Native source / transformation |
| --- | --- |
| `0x00..0x17` | Vector descriptor for 32-byte output rows from history `S+0xed8`. Each row is its original u64 key followed by the 24-byte result of `0x22bad90`. |
| `0x18..0x2f` | Vector descriptor for 64-byte output rows from history `S+0xdd0`. Each row is its original u64 key followed by the 56-byte result of `0x4dff980`. |
| `0x30..0x4f` | When selector byte=1, history `S+0xe38` passes through `0x2cfb470` with selector bytes+1..+20, then `0x2cfd5b0`. Otherwise the first word is `0x8000000000000001`; inactive payload bytes are not assigned semantic values. |
| `0x50..0x8f` | 64-byte helper result from `0x24b7700`, given the same original wrapper. Its inner semantics remain a dependency. |
| `0x90..0x97` | Direct copy of `S+0x30`. Its protocol name is unproved. |
| `0x98..0xaf` | 24-byte result of `0x22bad90` over the container at `S+0xf08`. |

The final assembly is `0x2af6f8b..0x2af7092`. These are native descriptors and tagged values, not a portable wire format. Inactive words must not be compared as initialized semantic payload.

## First history

The descriptor at `S+0xed8` uses a minimum-i64 sentinel to select a tree representation; that iterator remains opaque (`0x239a110`). Otherwise it contains capacity, pointer, head and length at offsets +0/+8/+0x10/+0x18. Native flat iteration uses **32-byte source rows**.

For a valid nonempty ring, the head is normalized by subtracting capacity once when head>=capacity. The code constructs two physical slices, one from the normalized head toward the allocation end and one wrapping to index zero. It consumes the second slice backward, then the first slice backward. This is reverse logical insertion order, without requiring that keys be sorted.

When cutoff bit 0 is set, `0x2af6783..0x2af6789` reads the u64 row key and terminates the **whole scan** at the first key <= bounds+8. This is unsigned and includes equality. It is not a filter that resumes after a failing key. Without an active cutoff, it visits the full history.

Every visited row is included even if its nested payload is empty. `0x22bad90` projects the nested container at source row+8; the result is joined to the original key and appended as a 32-byte output row. The sorting, allocation and semantic identity of that nested container are not implemented here.

## Second history

The descriptor at `S+0xdd0` uses the same flat/two-slice construction with **80-byte source rows**, or the unresolved tree iterator `0x239a690` for its sentinel representation. It has its own bound at bounds+0x10.

The selected order is precise:

1. Visit a row backward.
2. If enabled, stop at its key <= the second bound (`0x2af6b91..0x2af6b97`).
3. Skip the row if the u64 at **source row+0x30** is zero (`0x2af6b9d`; `rdx` already points at row+8).
4. Otherwise invoke the actual projector `0x4dff980` through relocation slot `0x64e74f0`, with the byte at `S+0xb9a`, the payload at row+8, and context `S+0xd88`.
5. Append the original key and the 56-byte helper result as one 64-byte output row.

Consequently an empty row at or below the cutoff still terminates scanning; the empty-payload check cannot be moved ahead of the cutoff. An empty row above the cutoff is skipped and scanning continues. No monotonic-key invariant is required to reproduce these branches, though such an invariant may be needed by downstream interpretation.

## Source-owned boundary and validation

`src/node115-execution-history-selection` implements exactly the flat-row membership/order boundary and returns physical slot indices. It reads raw little-endian row keys and the second history's raw nonempty word. It has no callbacks standing in for native projectors and makes no claim to construct the complete 176-byte result.

The source API admits initialized rings with length<=capacity and a nonempty head within the native single-wrap domain. Empty rings ignore head, as the native initialization does. Invalid safe-API inputs return explicit errors; this does not invent behavior for invalid native pointers or descriptors. Tree histories and owned payload construction are outside the API.

```sh
python3 research/work-items/RE-008-node115-execution-history-producer/verify.py --target /path/to/original/hl-node
cargo test --manifest-path src/node115-execution-history-selection/Cargo.toml
cargo test --release --manifest-path src/node115-execution-history-selection/Cargo.toml
cargo clippy --manifest-path src/node115-execution-history-selection/Cargo.toml --all-targets -- -D warnings
```

The static verifier checks the complete target digest, three windows containing 2852 bytes/592 instructions, and 193 facts with 193 rejected corruption controls. The three Rust tests cover all small physical wrap layouts against an independently constructed logical-order oracle, unsigned boundaries, equality, empty history and inactive head, and a deliberately nonmonotonic history demonstrating stop-versus-filter behavior and cutoff-before-empty ordering.

Remaining work includes actual state-field identities and producers, tree iteration, all nested helper semantics, concurrent snapshot ownership, complete result domains, and integration with the existing selector. No captured native code was executed or emulated.
