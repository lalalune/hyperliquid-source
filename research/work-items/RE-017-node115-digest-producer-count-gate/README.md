# Node #115: digest producer's membership-count gate

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This examines the second gate of the selected `0x5373e40` producer after the `0x36c7f70` result covered by #6611; it is distinct from the related `0x5374b70` vote walker in #6051.

The producer loads a binary64 factor from its `rsi+0x38` at `0x5373f78` and stores a pointer read from `rcx` at `0x5373f86`. After the first helper returns nonzero it obtains an object through `0x5349140`. At `0x53743b6..0x53743d3`, both positive and negative zero bypass the counting path with the gate flag set; an unordered factor, including NaN, enters the counting path.

On that path the selected iterator yields 20-byte entries. At `0x5374620..0x5374710`, the code searches the separate object from the saved pointer, comparing all 20 bytes through the `memcmp` relocation at `0x64dfb50`. An exact match contributes one to `r11`; absent entries contribute zero. `0x5374469` accumulates with carry sent to a separate overflow branch. At `0x5374780..0x53747d0`, the unsigned accumulated count and the qword at saved-object `+0x10` are converted to binary64, the latter is multiplied by the factor, and `seta` tests strict greater-than. Unordered comparison makes the flag false. After cleanup, false resumes the inner scan at `0x537482f`.

Thus under valid iterator and search-tree invariants, normal returns and no count overflow, the nonzero-factor branch requires `float(matched_count) > float(object_word_at_0x10) * factor`. Values are rounded as binary64: this is not an exact integer ratio for all u64 values. The identity, authority and provenance of either object, NaN/overflow failure behavior beyond the selected branches, and the full admission policy remain open. In particular, this does not prove a canonical root, a network quorum or completed replay.

Run `python3 research/work-items/RE-017-node115-digest-producer-count-gate/verify.py` to check target digest, instruction anchors, direct-call and corruption controls without target execution. `windows.txt` contains the selected disassembly and comparator relocation.
