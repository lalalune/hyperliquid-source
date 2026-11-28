# Node #115 sysinfo process stat parsing

This RE-002 packet matches the complete catalogued Linux process stat parser to a separately compiled sysinfo reference. Released sysinfo 0.29.11 source splits the PID at the first space, locates the command name using the final right parenthesis and splits remaining fields on whitespace. Selected target instructions corroborate the delimiter characters and initial 52-entry capacity. This static evidence does not prove the exact production crate version or complete runtime equivalence.

Base `2da45cb0a761cff6b478e40421699857d87a94df`; target node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The verifier checks the source archive checksum and reads the ELF as data. Run from repository root: `python3 -B research/work-items/RE-002-node115-sysinfo-process-stat-parser/verify.py /path/to/vendor-source`. `offline-log.txt` is actual output; `MANIFEST.sha256` covers the packet.
