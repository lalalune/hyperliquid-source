# RE-009 — Node #115 quantity ordering run scan

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The large-ordering wrapper (#7547) calls the core at `0x3e73880`. The run scan in that core starts at `0x3e73a40`.

The scan examines unsigned first words at 24-byte intervals. A second key below the first selects a strictly decreasing run. Otherwise, the scan accepts an increasing run with ties. The first comparison that breaks the chosen ordering ends the run without including the row that broke it. When a run goes directly to publication, the decreasing branch swaps all three words in symmetric rows and advances the two pointers by one row on each iteration. Thus a directly published reversed run has ascending keys and retains both payload words with each key. Equal keys can remain adjacent in the increasing scan and never occur within a strictly decreasing run.

The two scan exits also check a minimum-run threshold. This packet verifies the direct scan and reversal path. Run extension and merging are outside its scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-ordering-run-scan/verify.py` to verify the bytes and synthetic run fixtures.
