# Validation against the integration base

Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Its Windows sweep ran 4979 tests across 583 files, with 293 failing files. The candidate ran 4980 tests across 584 files, with 293 failing files. The failure headers agree. The additional test ran the real Rust compiler and passed.

Required command exits: doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1. The repository-wide packet check reports the same existing consensus log digest mismatch at base and candidate. The Rust library also passed offline locked Cargo check for Linux x86-64.

Base test log SHA-256: `43f989f9df90f7e697e8096a98621473a12f13d2993ddf2fe5aee980ea3e5927`.

Candidate test log SHA-256: `7a6faeea9ddfb2482f832b8243c0d9a99bcf4e5623274c10dac5fe6a65a2ea49`.
