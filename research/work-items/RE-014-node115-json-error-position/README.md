# Node #115 JSON error position and wrapper replacement

Partial backlog HL115-087, RE-014. Target node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This closes the position calculation and normal wrapper-replacement dependency left by margin-mode reader evidence, with a precise CPU-path premise. It does not change enum interpretation or claim complete JSON decoding.

## Prior work and gap

[#3388](https://github.com/lalalune/hyperliquid-source/pull/3388) and [#4236](https://github.com/lalalune/hyperliquid-source/pull/4236) establish reader paths; [#5088](https://github.com/lalalune/hyperliquid-source/pull/5088) concerns caller-level enum interpretation. Open [#5420](https://github.com/lalalune/hyperliquid-source/pull/5420) handles `0x4671240` while leaving `0x5c56920` supplied. [#5576](https://github.com/lalalune/hyperliquid-source/pull/5576) reconstructs the selected string scanner, stopping before error-position construction. Those are credited context, not new claims here. This packet resolves `0x5c56920` through the selected reverse-search/count implementations and the `0x2cf8390` ownership path. No source from an open PR is copied or required.

## Observed chain

`0x2cf8390` examines the error object's u64 at +0x18. A nonzero value returns the original pointer with no reader access. Otherwise it calls `0x1d77b20`, which reads input pointer +0x18, input length +0x20 and cursor +0x28, then calls `0x5c56920`.

For cursor <= length, that helper searches the prefix ending at cursor for the last LF byte (`0x0a`). Let `start` be one past the match, or zero if absent. It counts LF in input[0..start], returns line = count + 1 and column = cursor - start. A cursor immediately after LF is therefore column zero on the next line. CR is an ordinary byte, and a cursor inside a UTF-8 encoding is counted in bytes. Cursor > length reaches a diagnostic boundary, not a position result.

The reverse and count calls go through writable function caches. Their initial relocation values name dispatchers `0x47562d0` and `0x4756570`. Both inspect CPU-cache bit15; this contribution follows the clear-bit choices `0x4756370` and `0x47569d0`. The reverse implementation searches backward using scalar bytes and 16-byte masks; `bsr` picks the last matching byte and the rightmost of four blocks is tested first. The count implementation handles scalar head/tail and 16-byte masks, summing their bit counts using the 0x5555/0x3333/0x0f0f stages. The packet binds both complete selected implementations and the dispatcher/cache edges. Valid slices, selected implementation identities and successful allocation are premises; it does not assert which CPU branch a live process uses or prove cache concurrency/AVX behavior.

`0x1d77b20` tail-calls `0x5c54800`: copy 24 opaque payload bytes, place line at +0x18 and column at +0x20, allocate a new 40-byte wrapper and copy those fields. Only after that returns does `0x2cf8390` release the old 40-byte wrapper and return the replacement. The normal path moves the opaque payload representation without invoking its destructor. Native payload ownership internals, allocation failure and unwind destructors remain open.

The actual margin key reader `0x1def7c0` sends shared-scanner result tag2 and its unknown-key error into `0x2cf8390` at `0x1def969`, then stores error tag3. Other branches use different constructors; this does not assign every parser error the same finishing path. The distinct value reader from #4236 also must not be assumed to use this wrapper path for all scanner failures.

## Authored source and validation

`src/node115-json-error-position` supplies the position calculation and an owned 40-byte error wrapper. Already-positioned errors retain pointer identity and all bytes; replacements preserve the opaque payload and allocate before releasing the old wrapper. Invalid cursors explicitly stop before native diagnostics. The Rust allocation API is a logical ownership model, not a replacement for the captured allocator or arbitrary pointer-bearing payload destructors.

Run `python3 research/work-items/RE-014-node115-json-error-position/verify.py --target <pinned-node-115>` and `cargo test --manifest-path src/node115-json-error-position/Cargo.toml` (also `--release`). The packet authenticates 2,449 bytes / 676 instructions in nine windows, relocations and 27 semantic corruption controls. Five Rust tests cover 98,305 short newline-pattern/cursor pairs against a forward scan, CR/UTF-8 byte columns, existing-position bypass, replacement identity/payload preservation and invalid-cursor ownership. No captured code is executed or emulated. Static/source evidence is bounded; full component gates remain false.
