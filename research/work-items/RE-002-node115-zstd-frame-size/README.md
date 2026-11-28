# Zstandard frame content-size fields in node #115

The registered 641-byte ZSTD_getFrameContentSize body has eight relocation fields. The existing streaming linkage packet identified six call destinations. The two remaining fields reference width tables that govern which bytes of a modern frame header carry its content size. The reference body, six earlier call destinations, and both table addresses reproduce all 641 bytes.

| Instruction | Destination in .rodata | Four little-endian size_t entries | Frame descriptor |
| --- | --- | --- | --- |
| 0x628c844 | 0x9831a0 | 0, 2, 4, 8 | Contents-size flag, bits 7–6 |
| 0x628c86f | 0x983180 | 0, 1, 2, 4 | Dictionary-ID flag, bits 1–0 |

Both complete 32-byte tables agree with the named declarations in the two candidate zstd-sys archives. Their addresses are read from the captured instructions. The compiler loads a table entry with an eight-byte stride at 0x628c86b and 0x628c876. For a single-segment header the otherwise absent size field becomes one byte. For a two-byte size, the target zero-extends the field and adds 256 at 0x628c92f. The four- and eight-byte branches read their widths directly. For an omitted size in a multi-segment frame, the function returns the unknown-size sentinel. The full source and target body hashes and table digests are in [result.json](result.json). The [preceding streaming linkage packet](../RE-002-node115-native-zstd-stream-linkage/README.md) identifies the legacy parser and support calls.

The public-library check constructs all 64 current descriptor combinations with both unused/reserved bits zero. It supplies a dictionary ID when encoded and exercises sizes spanning zero, midpoints and boundaries, including zero-length, unknown and the two-byte bias. Across 160 header vectors the public 1.5.7 size and header APIs agreed on the content size, and the parsed dictionary ID, checksum flag and header length matched the inputs. These calls parse only the headers. No dictionary load or frame decompression is required. See the [Zstandard frame format](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1) and [1.5.7 API](https://github.com/facebook/zstd/blob/v1.5.7/lib/zstd.h).

## Replay

Materialize the repository's authenticated node #115 first. Supply a host-native public libzstd 1.5.7 and both published crates. Run from this packet directory.

```sh
curl -fLo zstd-a.crate 'https://static.crates.io/crates/zstd-sys/zstd-sys-2.0.15+zstd.1.5.7.crate'
curl -fLo zstd-b.crate 'https://static.crates.io/crates/zstd-sys/zstd-sys-2.1.2+zstd.1.5.7.crate'
python3 -B verify.py /path/to/libzstd.so.1.5.7 zstd-a.crate zstd-b.crate
```

Verified on arm64 macOS using the host libzstd. The archive hashes are the two accepted candidate checksums from the vendor census. The target is the Linux x86-64 node with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Only the public library is executed. The existing function window and prior direct-call findings retain their original attribution. The comparison establishes no unique crate release, legacy frame behavior or storage caller reachability. No coverage or component gate changes.

The new analysis code uses the repository license. Public crate sources and libzstd are obtained separately.
