# What the second reader of the digest side was asked (round 4)

A Claude subagent (Anthropic, the same model family as the author of this packet, started with an empty
context) received the text below. It differs from the original only where an absolute file path stood: those
are written as `<repository>/...`. The reader had `objdump`, Python and a shell, no network, and was told not to
read this packet, the crate, or any notes. It was given the frame layout and the addresses of the functions the
two entry points call (they come from the author's own reading, so this check is not blind about the structure),
but none of the expected values: not the preimages, not the digests, not the recovery table.

The five frames F1..F5 are rows `d0013`, `d0014`, `d0199`, `d0200`, `d0201` of `cases-digest.tsv`, chosen
by the author before asking (a varint of each class, the largest class twice, random values).

---

You are a static reverse-engineering reader. Question: what bytes does one function of a stripped x86-64 Linux ELF hash, and what does a second function do with a signature? You must derive the answer ONLY from the binary's machine code (use `objdump -d --no-show-raw-insn --start-address=0x... --stop-address=0x...`, `objdump -s` for rodata/jump tables, and your own reasoning/Python for arithmetic). The binary is at `<repository>/artifacts/node/115/hl-node` (sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

HARD RULES: Do NOT execute, emulate or debug the binary. No network. Do NOT read anything under the directory of the RE-008 nested-certificate-decision packet or the source directory of the crate node115-nested-certificate-decision, nor the output directories of earlier rounds, nor any memory/notes directory: they hold someone else's expected answers and reading them would void this independent check. Do not search the repository for the addresses below. Do not write files. In your final answer do not write absolute file paths; call the binary `hl-node`. Work for at most about 30 minutes of effort and be concise.

Facts you may rely on (link-time virtual addresses; GOT-style slots like 0x64e0148 hold an R_X86_64_RELATIVE addend you can read from .rela.dyn using a small python parse of the ELF if you need it; I tell you the ones you need):
- Function D = 0x57e8d40 is a digest builder: D(out32, msg). `msg` is a 16-byte struct {word0 = message variant, word1 = pointer to a frame}. For this question word0 = 1.
- The frame (0x5c bytes) has this layout: +0x00 32-byte hash H; +0x20 u64 A; +0x28 u64 B; +0x30 u64 C; +0x38 u64 D; +0x40 u64 E; +0x48 20-byte address S (all u64 little endian in memory).
- D calls 0x5823db0 (a serializer, also look at what it calls for variant 1), 0x5b3df10, and a hasher through slots 0x64e0148 (addend 0x5cda910) and 0x64e0150 (addend 0x5cdad40); the permutation they call is at 0x5cda380 (you do not need to re-derive that permutation's round function; just tell me what it is if you recognize it, with one sentence of evidence). Ignore calls to 0x5c842e0 / 0x5c84210 unless they influence the hashed bytes.
- Function R = 0x1536a90 is the target of slot 0x64e0ad8: R(out, sig, digest). `sig` points to 65 bytes, `digest` to 32 bytes. `out` is a Result-like record: byte 0 is the tag (0 = Ok) and on Ok the 20 bytes at out+1 are the result. R calls three functions through slots 0x64df9d8 (0x632b660), 0x64df9e0 (0x632b7b0), 0x64df9e8 (0x632b480).

Questions:
Q1. For each frame F1..F5 below (message variant 1), give the exact byte string that D hands to the hash function, as one lowercase hex string, in order, with a one-line justification of the encoding rules you inferred (field order, how each of A..E is encoded as a function of its value, whether lengths or tags are written, what precedes the serialized frame). Also state the hash function parameters (rate in bytes, padding/delimiter byte, output length) and the evidence address for each.
F1: S=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3 A=0x100000001 B=0x9 C=0xb D=0xd E=0xf H=303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
F2: same as F1 except A=0x8000000000000000
F3: S=05a1a30cc0759e324473d9b5406bef60c2b71cda A=0x4e252f3 B=0x7 C=0x9c92e59e D=0x1e4e821d2 E=0x74397c924419 H=34eb20a51b4f823e3e03a937e910ba11faa663515d9e3e85fdf5d8e86d8c76a6
F4: S=bbfd414f36424208e15c66b2d3b6a92528cbd2e5 A=0xee B=0x946 C=0xa6 D=0xc3915 E=0x2a129 H=4ab007185b6d5211795618b3888370070c1fcc7f53ad9d71c394401389e27c48
F5: S=be1e8d49f7f8fe56597755cd99ce059a4e8e23f2 A=0x7d8 B=0x4b31ff5c C=0xf11dd D=0x138 E=0xa0 H=2982fff216719398a493c065c98f3deadeac7930e05f44170b36997d60c16b79

Q2. What does R do with the 65 signature bytes: which bytes become what (byte order of each 32-byte half as passed on), and for the last byte v give, for v in {0,1,2,26,27,28,29,34,35,36,37,254,255}, the recovery id that is passed on or "error without calling the library functions". What are the three called functions (name them only if the bytes you see justify it, and say what you based the name on)? What exactly does R put at out+1..out+20 on success (which hash of which bytes, which slice)? What kinds of failure give a non-zero tag?

Answer format: a short markdown report with a table for Q1 (frame, preimage hex) and a table for Q2, then a list "Not verified / uncertain". Cite addresses for every rule.
