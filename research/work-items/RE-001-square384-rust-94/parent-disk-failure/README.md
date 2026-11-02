# Interrupted parent replay

The parent independently launched the committed validator with Python `-O` at
commit `5b7d841bf330408372669bc378efe566da618796`, writing to
`work/square384-parent-review` (session77742). It completed all four correct
builds and28 normally exiting effective mutant runs. The next mutant,
`big-endian-store`, failed while linking its input-only client because macOS
`ld` reported `write() failed, errno=28`. The validator exited1. The failed link
does not count as an effective mutant or a complete parent qualification.

`commands-partial.json` preserves the exact66 recorded compilation commands,
statuses and combined compiler output. `compiler-output.txt` preserves the
failing command's exact output. `failed-build-sources.json` preserves the actual
mutated library and client source. The original failed output directory is also
retained; no unique failure output was deleted.

`raw-streams.json.gz` retains all32 completed native stdout streams using the
same deterministic lossless shared-line schema as the final qualification.
Every stream was reconstructed and byte-compared with its original per-stream
gzip output. The four correct outputs match the frozen expectations; each of
the28 completed mutants differs. `record.json` records counts, all stream hashes,
archive/command hashes and the unchanged source/oracle/freeze identities.

Disk recovery removed only completed compiler outputs and byte-verified
archive duplicates from earlier own qualifications, with path/size/hash
journals. Existing same-hash Git LFS objects supplied verified APFS CoW archive
clones. Source, oracle, fixtures and validator were unchanged for the subsequent
fresh-directory optimized replay; its result is documented separately.
