# Retained qualification correction

The first integrity-normal run rejected its own negative-control setup with
Changed evidence accepted. The first sorted data record is the one-byte NUL
at61a6f. The inherited summary-data mutation assigned00, equal to its original
value, so it was a neutral fixture rather than corrupted evidence. No target
comparison or positive result failed. The source was corrected to XOR the
actual first data byte. Original source, failed command/log and journal remain
in the operator evidence. The repaired integrity run and subsequent optimized
run must pass; original native, mathematical and frozen expectation records
remain unchanged. VALIDATION.json reports both the failure and repair.
