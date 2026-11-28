# Node #115 sysinfo user enumeration

This RE-002 packet matches the catalogued user enumeration body to a separately compiled sysinfo reference. Released sysinfo 0.29.11 source reads `/etc/passwd`, parses user and group IDs and looks up group membership. The offline verifier confirms the complete non-relocation byte comparison, the embedded passwd path instructions, and source-consistent buffer capacities. It does not read local user data or prove runtime equivalence or the exact production crate version.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; target node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF only as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-sysinfo-users-enumeration/verify.py /path/to/vendor-source`. `offline-log.txt` is the actual output; `MANIFEST.sha256` covers the packet.
