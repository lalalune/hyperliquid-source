# RE-017: flat pending-map digest selection (#115)

## Question and scope

Merged #5157 traces the selected tree traversal from the tracker to digest extraction; #6626 identifies that path's sentinel condition. Does the non-sentinel pending-map representation reach the same extraction, and what inputs does it pass? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. FDEs: `0x57f1690..0x57f1874`, `0x57d44d0..0x57d4aea`.

## Observations

The tracker drain `0x5afa030` constructs a seven-word callback context containing the tracker at `+8` and calls `0x4de0540` with tracker `+0x60` and that context. When `0 - [map]` does **not** set signed overflow (the leading qword is not `0x8000000000000000`), `0x4de05f7` passes the unchanged context as the second argument to `0x57f1690`. This is the alternative to the sentinel tree route in #6626.

`0x57f1690` reads map `+0x18` as its iteration bound and uses 24-byte-stride entries with a wrapped index based on map `+0`, `+8`, and `+0x10`. Each selected entry is passed with the context to `0x57d44d0` at `0x57f16f7`. Under a valid flat representation and normal returns, the callback reads the entry's first qword as a key and the following 12 bytes as a three-word input. It constructs a first threshold using the f64 pointer at context `+0x18`; its three-word comparison at `0x57d461a..0x57d4675` uses a signed first word and unsigned second and third words. On the greater-or-equal branch it passes the tracker from context `+8` and the exact saved entry key to `0x5377df0` (`0x57d467f..0x57d4698`). The returned sentinel is tested at `0x57d469d..0x57d46a6`; extraction is not guaranteed to return a digest.

If the primary comparison is earlier, execution instead enters a second threshold construction using f64 `60.0` (`0x57d4784..0x57d47a6`); its further behavior is not established here. This packet does not assert that the flat and tree representations are interchangeable, that any real checkpoint uses this route, or that timer inputs, authentication, finality or state roots are correct. Valid pointers, ring bounds, no interference and normal helper returns are assumptions. No completion gate is advanced.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-flat-digest-selection/verify.py` to authenticate the target and check eight instruction anchors, four direct calls and eight independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 with `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. This is static analysis; no target code is executed.
