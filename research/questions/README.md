# Bounded reconstruction questions

This five-record pilot exists to unblock a concrete #115 task: connecting the
selected checkpoint restore and first replay path to a root-validation fixture.
The broad queue (`docs/TASKS.md`) and component epic (#3923) do not identify that
work's exact prerequisites or remaining gaps. The evidence is spread across
merged #3988, #4011, #4117, and #4157, plus open #5584 and #5591. In particular,
#4157 leaves the external H+1 expected-root source unresolved, while #5584 and
#5591 record related selector and selected-writer attempts without a shared
dependency record. This made it possible to start downstream fixture work
without a required input contract, or repeat the manual history audit.

## Record contract

Each `qcp-*.json` record is bound to the exact node #115 artifact and component.
It contains:

- a stable ID, question, work type, include/exclude boundary, and separate
  readiness and evidence statuses;
- prior pull requests with their relationship to this question;
- a plain description of the remaining gap;
- hard or soft dependencies, each with a required contract and condition;
- a shared downstream consumer and concrete acceptance requirements;
- required capabilities, reviewed evidence, the active component issue, and
  the pilot issue.

`schema.json` describes the record fields. `tools/question_registry.py`
validates the five-record pilot, target digest,
component IDs, reference formats, required fields, dependency IDs, and hard
dependency cycles. `make catalogue` includes the generated JSON and
`docs/QUESTIONS.md`; `make catalogue-check` verifies both are current. The
questions never set the four component gates in `research/progress.json`.

## Read-only ownership and review context

Run `make question-ownership-refresh` to fetch linked issue assignments and
attempt PR state, author, requested reviewers, and reviews on the current PR
head through the installed `gh` command. It performs GET requests only; it does
not create or edit issues, comments, labels, or assignments. Then run
`make catalogue` to regenerate the views. The snapshot timestamp and a
30-minute freshness limit are retained. `python3 tools/question_registry.py
--status` reports whether the snapshot is currently fresh. Stale or missing
data is **unknown**. An open PR's author is displayed as an attempt author, not
as an exclusive task owner.

## Reservation and handoff

The pilot does not assign an owner. A maintainer must designate one coordinator
before reservations become active. Only that coordinator serializes grants and
updates the linked GitHub issue. A grant records the question ID and definition
revision, owner, reservation revision, UTC grant and expiry, latest progress or
handoff link, and any superseded reservation. An expired or superseded grant
cannot renew itself; reassignment preserves earlier work and references. Until
a coordinator grant is recorded, reservation state remains unknown. This
protocol avoids treating a question record or PR author as a claim.

Independent verification may overlap another question's binary range when its
scope and comparison are explicit. Contradictory evidence links to the earlier
claim and flags affected consumers for review; it never rewrites accepted
evidence or progress automatically.

## Pilot outcome

The records make the next gaps and their dependencies explicit. The pilot does
not yet demonstrate active reservation grants, two concurrent claim attempts,
expiry, or reassignment in a live coordinator workflow; no coordinator has
been designated in the linked issue. Those remain adoption checks for the
maintainers. The registry is not an automated semantic-approval system.
