# Node #115 HTTP response reason and version parsing

This RE-002 packet examines HTTP response-line reason and version parsing against httparse 1.10.1. The released source distinguishes partial HTTP/1 version input, accepts HTTP/1.0 and HTTP/1.1, and handles reason text with line termination and an empty fallback for non-ASCII text. The verifier compares both complete catalogued target bodies with their compiled reference outside relocation fields. These observations do not establish an exact production crate version or runtime equivalence.

The earlier decimal cursor packet excludes the adjacent reason-parser entry; these parser bodies are distinct. Base `2da45cb0a761cff6b478e40421699857d87a94df`; node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. From repository root run `python3 -B research/work-items/RE-002-node115-httparse-response-line/verify.py /path/to/vendor-source`. The log is actual offline output; the manifest covers the packet.
