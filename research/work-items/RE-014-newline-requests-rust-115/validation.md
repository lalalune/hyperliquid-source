The same-base comparison uses 05bc2de303c05525b71e7e257426e741bc66a390.
The base reported 4979 tests from 583 files,
with 293 failing files. The candidate reported
4985 tests from 584 files, with
293 failing files. No failure header was added.
All six added methods passed with the actual Rust 1.94.1 compiler enabled.

Required command exits were doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1. Existing Windows verification
and suite failures are retained as failures. The generated catalogue passes
after the contribution is indexed. The candidate full-suite log SHA-256 is
`e15dbc631160eeaa148f236df0e9763fdde4e977c3c61609779bada14e4862d3`. The base log SHA-256 is `43f989f9df90f7e697e8096a98621473a12f13d2993ddf2fe5aee980ea3e5927`.
The offline, locked Rust library build targets Linux x86-64.

The initial 8fd8db68-based suite exposed an assertion that compared in-memory
tuples with lists read from JSON. The corrected test compares the serialized
representation. Both the corrected old-base suite and this integration run
use the corrected test. The Rust implementation and comparison tool were
carried forward byte-for-byte. The native oracle, frozen vectors and evaluator
dependencies are identical at the two bases.
