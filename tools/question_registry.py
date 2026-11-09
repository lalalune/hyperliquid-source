#!/usr/bin/env python3
"""Validate and render the bounded #115 checkpoint/replay question pilot."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = "lalalune/hyperliquid-source"
SNAPSHOT_MAX_AGE_SECONDS = 1800
QUESTION_ID = re.compile(r"^qcp-[a-z0-9]+(?:-[a-z0-9]+)*$")
PR_REF = re.compile(r"^https://github\.com/lalalune/hyperliquid-source/pull/(\d+)$")
ISSUE_REF = re.compile(r"^https://github\.com/lalalune/hyperliquid-source/issues/(\d+)$")
READINESS = {"ready", "in-progress", "blocked", "recorded"}
EVIDENCE_STATES = {"not-started", "unreviewed", "partial", "reviewed"}
REQUIRED = {
    "question_id", "title", "target", "component", "work_type", "scope",
    "readiness", "evidence_status", "prior_attempts", "remaining_gap", "dependencies",
    "downstream_consumer", "acceptance_requirements", "required_capabilities",
    "evidence_review", "linked_issue", "pilot_issue",
}


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot read {path.relative_to(ROOT)}: {error}") from error


def load_questions(root=ROOT):
    directory = root / "research/questions"
    schema = read_json(directory / "schema.json")
    if (set(schema.get("required", [])) != REQUIRED
            or set(schema.get("properties", {})) != REQUIRED):
        raise ValueError("schema.json fields differ from the executable question validator")
    questions = []
    for path in sorted(directory.glob("qcp-*.json")):
        row = read_json(path)
        if not isinstance(row, dict) or set(row) != REQUIRED:
            raise ValueError(f"{path.name}: fields must be exactly {sorted(REQUIRED)}")
        if (not isinstance(row["question_id"], str) or not QUESTION_ID.fullmatch(row["question_id"])
                or path.stem != row["question_id"]):
            raise ValueError(f"{path.name}: question ID does not match its filename")
        if not isinstance(row["readiness"], str) or row["readiness"] not in READINESS:
            raise ValueError(f"{path.name}: invalid readiness state")
        if not isinstance(row["evidence_status"], str) or row["evidence_status"] not in EVIDENCE_STATES:
            raise ValueError(f"{path.name}: invalid evidence status")
        if (not isinstance(row["work_type"], str)
                or row["work_type"] not in {"discovery", "reconstruction", "verification", "integration"}):
            raise ValueError(f"{path.name}: invalid work type")
        artifact = row["target"]
        if (not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}
                or artifact["path"] != "artifacts/node/115/hl-node"):
            raise ValueError(f"{path.name}: target must identify the node #115 artifact")
        inventory = read_json(root / "provenance/artifacts.json")
        pinned = next((item for item in inventory["files"] if item["path"] == artifact["path"]), None)
        if not pinned or artifact["sha256"] != pinned["sha256"]:
            raise ValueError(f"{path.name}: target digest differs from provenance/artifacts.json")
        component_ids = {item["id"] for item in read_json(root / "research/components.json")["components"]}
        if not isinstance(row["component"], str) or row["component"] not in component_ids:
            raise ValueError(f"{path.name}: unknown component {row['component']!r}")
        for key in ("title", "remaining_gap", "downstream_consumer"):
            if not isinstance(row[key], str) or not row[key].strip():
                raise ValueError(f"{path.name}: {key} must be a non-empty string")
        scope = row["scope"]
        if (not isinstance(scope, dict) or set(scope) != {"question", "include", "exclude"}
                or not isinstance(scope["question"], str) or not scope["question"].strip()
                or not all(isinstance(scope[key], list) and scope[key]
                           and all(isinstance(item, str) and item.strip() for item in scope[key])
                           for key in ("include", "exclude"))):
            raise ValueError(f"{path.name}: question and non-empty include/exclude boundaries are required")
        if (not isinstance(row["acceptance_requirements"], list) or not row["acceptance_requirements"]
                or not all(isinstance(item, str) and item.strip() for item in row["acceptance_requirements"])):
            raise ValueError(f"{path.name}: acceptance requirements are required")
        if (not isinstance(row["required_capabilities"], list) or not row["required_capabilities"]
                or not all(isinstance(item, str) and item.strip() for item in row["required_capabilities"])):
            raise ValueError(f"{path.name}: required capabilities are required")
        if (not isinstance(row["prior_attempts"], list) or not isinstance(row["evidence_review"], list)
                or not isinstance(row["dependencies"], list)):
            raise ValueError(f"{path.name}: attempts and evidence must be lists")
        for attempt in row["prior_attempts"]:
            if (not isinstance(attempt, dict) or set(attempt) != {"url", "relation"}
                    or not isinstance(attempt["url"], str) or not PR_REF.fullmatch(attempt["url"])
                    or not isinstance(attempt["relation"], str) or not attempt["relation"].strip()):
                raise ValueError(f"{path.name}: invalid prior pull request reference")
        if (not isinstance(row["linked_issue"], dict) or set(row["linked_issue"]) != {"url", "purpose"}
                or not isinstance(row["linked_issue"].get("url"), str)
                or not isinstance(row["linked_issue"].get("purpose"), str)
                or not row["linked_issue"]["purpose"].strip()):
            raise ValueError(f"{path.name}: linked issue and purpose are required")
        if not ISSUE_REF.fullmatch(row["linked_issue"]["url"]):
            raise ValueError(f"{path.name}: invalid linked issue URL")
        for review in row["evidence_review"]:
            if (not isinstance(review, dict) or set(review) != {"url", "decision"}
                    or not isinstance(review["url"], str) or not PR_REF.fullmatch(review["url"])
                    or not isinstance(review["decision"], str) or not review["decision"].strip()):
                raise ValueError(f"{path.name}: invalid evidence review reference")
        if row["pilot_issue"] != "https://github.com/lalalune/hyperliquid-source/issues/5391":
            raise ValueError(f"{path.name}: pilot issue must reference #5391")
        for dep in row["dependencies"]:
            if (not isinstance(dep, dict) or set(dep) != {"question_id", "kind", "contract", "condition"}
                    or not isinstance(dep["kind"], str) or dep["kind"] not in {"hard", "soft"}
                    or not all(isinstance(dep[key], str) and dep[key].strip()
                               for key in ("question_id", "contract", "condition"))):
                raise ValueError(f"{path.name}: invalid dependency contract")
        questions.append(row)
    ids = [row["question_id"] for row in questions]
    if len(questions) != 5 or len(set(ids)) != len(ids):
        raise ValueError("the checkpoint/replay pilot must contain exactly five unique records")
    known = set(ids)
    graph = {}
    for row in questions:
        graph[row["question_id"]] = []
        for dep in row["dependencies"]:
            if dep["question_id"] not in known:
                raise ValueError(f"{row['question_id']}: missing dependency {dep['question_id']}")
            if dep["kind"] == "hard":
                graph[row["question_id"]].append(dep["question_id"])
    visiting, visited = set(), set()

    def visit(question_id):
        if question_id in visiting:
            raise ValueError(f"hard dependency cycle includes {question_id}")
        if question_id in visited:
            return
        visiting.add(question_id)
        for dependency in graph[question_id]:
            visit(dependency)
        visiting.remove(question_id)
        visited.add(question_id)

    for question_id in ids:
        visit(question_id)
    return questions


def refresh_ownership(root=ROOT):
    questions = load_questions(root)
    issues = {"5391", "3923"}
    pulls = {match.group(1) for row in questions for attempt in row["prior_attempts"]
             if (match := PR_REF.fullmatch(attempt["url"]))}
    result = {"schema_version": 1, "source": "GitHub REST API via gh", "fetched_at":
              datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
              "issues": {}, "pull_requests": {}}
    for number in sorted(issues):
        raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/issues/{number}"], text=True)
        issue = json.loads(raw)
        result["issues"][number] = {
            "state": issue["state"], "assignees": [a["login"] for a in issue.get("assignees", [])],
            "url": issue["html_url"],
        }
    for number in sorted(pulls, key=int):
        raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/pulls/{number}"], text=True)
        pull = json.loads(raw)
        reviews_raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/pulls/{number}/reviews?per_page=100"], text=True)
        reviews = json.loads(reviews_raw)
        latest_by_reviewer = {}
        for review in reviews:
            if review.get("commit_id") == pull["head"]["sha"]:
                login = review.get("user", {}).get("login")
                if login and (login not in latest_by_reviewer or
                              review.get("submitted_at", "") > latest_by_reviewer[login].get("submitted_at", "")):
                    latest_by_reviewer[login] = review
        current_states = {review.get("state") for review in latest_by_reviewer.values()}
        requested_raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/pulls/{number}/requested_reviewers"], text=True)
        requested = json.loads(requested_raw).get("users", [])
        if pull.get("merged_at"):
            review_state = "merged"
        elif "CHANGES_REQUESTED" in current_states:
            review_state = "changes-requested"
        elif requested:
            review_state = "review-requested"
        elif "APPROVED" in current_states:
            review_state = "approved-on-current-head"
        else:
            review_state = "no-approval-on-current-head"
        result["pull_requests"][number] = {
            "state": "merged" if pull.get("merged_at") else pull["state"],
            "author": pull["user"]["login"], "url": pull["html_url"],
            "review_state": review_state,
        }
    path = root / "research/questions/ownership-snapshot.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Fetched read-only GitHub ownership context for {len(issues)} issues and {len(pulls)} pull requests.")


def read_ownership_snapshot(root):
    path = root / "research/questions/ownership-snapshot.json"
    if not path.is_file():
        return None
    try:
        data = read_json(path)
        fetched = datetime.fromisoformat(data["fetched_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(data.get("issues"), dict) or not isinstance(data.get("pull_requests"), dict):
        return None
    return data


def snapshot_state(root):
    data = read_ownership_snapshot(root)
    if data is None:
        return None, "unknown (no valid ownership snapshot)"
    fetched = datetime.fromisoformat(data["fetched_at"].replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - fetched).total_seconds()
    if age < 0 or age > SNAPSHOT_MAX_AGE_SECONDS:
        return None, f"unknown (ownership snapshot stale; fetched {data['fetched_at']})"
    return data, f"read-only GitHub snapshot fetched {data['fetched_at']} (fresh for 30 minutes)"


def render_question_catalogue(root=ROOT):
    questions = load_questions(root)
    snapshot = read_ownership_snapshot(root)
    freshness = (f"historical read-only GitHub context fetched {snapshot['fetched_at']}; "
                 "treat as stale after 30 minutes and run `python3 tools/question_registry.py --status`") if snapshot else "unknown (no valid ownership snapshot)"
    generated = {"schema_version": 1, "target": questions[0]["target"], "ownership_freshness": freshness,
                 "questions": questions}
    if snapshot:
        generated["ownership_snapshot"] = snapshot
    md = ["# Checkpoint/replay question pilot", "",
          "Generated by `make catalogue` from `research/questions/qcp-*.json`. Readiness, evidence status, and reservation are separate; none sets a component gate.", "",
          f"GitHub ownership: **{freshness}**. PR authorship is evidence of an open attempt, not a task reservation. When reservation state is unavailable, it is shown as unknown.", ""]
    for status, heading in (("ready", "Ready"), ("recorded", "Evidence-recorded"),
                            ("in-progress", "In progress"), ("blocked", "Blocked")):
        md.extend([f"## {heading}", ""])
        rows = [row for row in questions if row["readiness"] == status]
        if not rows:
            md.append("None currently identified.")
        for row in rows:
            md.extend([f"### {row['question_id']}: {row['title']}", "",
                       f"- Component: `{row['component']}`; work type: {row['work_type']}; readiness: **{status}**; evidence: **{row['evidence_status']}**.",
                       f"- Question: {row['scope']['question']}",
                       f"- Remaining gap: {row['remaining_gap']}",
                       f"- Downstream consumer: {row['downstream_consumer']}"])
            for attempt in row["prior_attempts"]:
                number = PR_REF.fullmatch(attempt["url"]).group(1)
                pull = snapshot["pull_requests"].get(number) if snapshot else None
                if pull and pull["state"] == "merged":
                    label = f"merged attempt by @{pull['author']} as of {snapshot['fetched_at']}"
                elif pull:
                    label = (f"{pull['state']} attempt by @{pull['author']}; {pull['review_state']} "
                             f"as of {snapshot['fetched_at']}")
                else:
                    label = "ownership unknown"
                md.append(f"- Prior attempt: [{attempt['url'].rsplit('/', 1)[-1]}]({attempt['url']}) — {attempt['relation']} ({label}).")
            for dep in row["dependencies"]:
                md.append(f"- {dep['kind'].title()} dependency `{dep['question_id']}`: {dep['condition']}")
            md.extend(["- Acceptance:", *[f"  - {item}" for item in row["acceptance_requirements"]], ""])
    md.extend(["## Reserved and review-needed", "",
               "Reservation: **unknown** until a maintainer-designated coordinator records a grant. An open PR and its author are shown as an attempt, not a task reservation.", "",
               "Review state: the snapshot records current-head approvals, requested reviewers, and changes requested. A missing or stale snapshot means review state is **unknown**, not unreviewed.", "",
               "Review-needed attempts:", ""])
    pending_review = []
    if snapshot:
        for number, pull in snapshot["pull_requests"].items():
            if pull["state"] == "open" and pull["review_state"] != "approved-on-current-head":
                pending_review.append(f"- [#{number}]({pull['url']}) — {pull['review_state']} as of {snapshot['fetched_at']}.")
    md.extend(pending_review or ["- Unknown; refresh the GitHub snapshot."])
    md.extend(["",
               "## Reservation protocol", "",
               "The pilot defines task scope and dependencies; it does not grant reservations. A maintainer must designate one coordinator before claims become active. Only that coordinator may serialize grants and update the linked GitHub issue. Each grant records the question ID and definition revision, owner, reservation revision, UTC grant and expiry, progress handoff, and superseded reservation. Expired or superseded grants require a new coordinator decision. If the coordinator or ownership lookup is unavailable, the view says **unknown**; absence of an assignment is not treated as proof of no work.", "",
               "Overlapping binary ranges remain eligible for explicitly independent verification. Contradictory evidence is linked for review; it does not silently overwrite an accepted finding.", ""])
    return json.dumps(generated, indent=2) + "\n", "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-ownership", action="store_true",
                        help="read current issue/PR metadata with gh; never writes to GitHub")
    parser.add_argument("--status", action="store_true", help="report whether the saved ownership snapshot is fresh")
    args = parser.parse_args()
    try:
        if args.refresh_ownership:
            refresh_ownership()
        elif args.status:
            snapshot, freshness = snapshot_state(ROOT)
            print(f"Reservation status: unknown (no coordinator grants are stored). Ownership context: {freshness}.")
        else:
            questions = load_questions()
            print(f"Validated {len(questions)} node #115 checkpoint/replay questions and their dependency graph.")
    except (ValueError, subprocess.CalledProcessError, FileNotFoundError) as error:
        print(f"question registry: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
