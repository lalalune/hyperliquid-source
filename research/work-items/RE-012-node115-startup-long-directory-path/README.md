# RE-012: long startup directory path and error handoff

- Component: node-runtime; bounded startup and failure-exit question under [issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927).
- Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Coordinates are linked ELF virtual addresses before load bias. Analysis reads bytes and metadata only; no target instructions or captured binary were executed.

## Question and result

The [directory admission packet](../RE-012-node115-startup-directory-admission/README.md) connects startup and nested wrappers to opener `0x5c9ca30`. The [directory ownership packet](../RE-012-directory-open-ownership-115/README.md) maps its stream/error result and says the long path uses a separate adapter, but does not interpret that adapter. This packet closes that selected adapter boundary, including the distinction between conversion failure and a null directory handle. It does not claim to map the filesystem, all opener effects, a working checkpoint or all cleanup and unwind behavior.

The opener compares its input length unsigned to `0x17f` (383): lengths 0–383 use its stack buffer; length 384 or greater calls `0x5c78e40` with the original pointer and length. Both directory wrapper `0x1501290` and nested wrapper `0x15021d0` reach the opener via relocation slot `0x64e0970`. The known startup-to-wrapper context is credited to the directory admission packet; it is not re-claimed here.

The long adapter passes its input to slot `0x64df718 -> 0x141e960`. It negates the first returned word: signed overflow, possible for the minimum signed word, selects the path that passes the returned pointer to imported `opendir`. After that call it saves the result, clears the first byte at the temporary pointer, and, if the saved size is nonzero, calls release slot `0x64df4a0 -> 0x635de30`; it returns `rax=0` and the saved `opendir` result in `rdx`. This statement is conditional on normal returns and valid converter output.

For every other first word, the adapter returns `rax=1` and a fixed pointer `0x64c2fb8`, with a release call when the negation's carry is set. Because `lea` and `mov` between the negation and `jae` do not overwrite flags, a zero first word skips that release; the minimum-signed-word path was already separated by overflow. The shared converter's interior-NUL behavior is prior work in [command construction](../RE-012-command-construction-115/README.md), not newly proved by the adapter alone.

The opener copies the adapter's tag into a low-bit test. Tag 1 returns the supplied error pointer with byte tag 2; tag 0 checks the handle. A null handle calls imported `__errno_location`, takes the 32-bit word, shifts it left 32 bits, ORs 2, and publishes that word with byte tag 2. On the long path the temporary-buffer cleanup above can occur **between** `opendir` and this errno read; on the selected short path the `opendir` call branches directly to the handle test. The bytes establish this ordering, not whether the actual release helper changes errno. Library versions, asynchronous interference and errno preservation remain unresolved. On a non-null handle, path copying and stream publication are credited to the existing ownership packet.

## Evidence and controls

Four indexed FDEs are retained: opener `[0x5c9ca30,0x5c9ccdb)` (683 bytes), long adapter `[0x5c78e40,0x5c78ec1)` (129 bytes), and wrappers `[0x1501290,0x150135b)` and `[0x15021d0,0x150229b)` (203 bytes each). Only the 129-byte adapter and its selected connection/error-order facts are new; other bodies are dependency context. The 1,218 bytes are evidence extent, not reconstructed node coverage. Raw GNU disassemblies are retained with trailing whitespace removed.

```sh
PYTHONPATH=tools python3 research/work-items/RE-012-node115-startup-long-directory-path/verify.py
(cd research/work-items/RE-012-node115-startup-long-directory-path && shasum -a 256 -c MANIFEST.sha256)
```

With Python 3.14.5 and GNU binutils 2.42, the verifier authenticates the full input, checks four indexed FDE/body hashes, 45 instruction spans, ten encoded targets, three relative relocations and two dynamic import names. Separate mutations to the length threshold, converter-status branch and buffer clear are rejected below the whole-body digest check. These are static corruption controls, not captured-target behavior tests. All results assume valid input slices and the stated ordinary helper returns; allocator internals, errno preservation, full C-string conversion, exception paths, host filesystem behavior and runtime reachability are not established. No implementation comparison or progress gate is requested. The next useful boundary is the release helper's actual errno effect under an authenticated target runtime, which would require separate execution authorization.
