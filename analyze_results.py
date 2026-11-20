"""Describe two-task participant pairs from export.py's CSV files.

Run: uv run python analyze_results.py
Results go to results/analysis. Task 2 is participant-selected, so mode effects are not isolated.
"""

import argparse
import csv
import io
import json
from collections import Counter, defaultdict
from importlib import import_module
from math import comb
from pathlib import Path
from statistics import mean, median

ROOT = Path(__file__).resolve().parent
VULNERABILITY_FIELDS = (
    "proposed_by_reviewer", "undecided", "accepted", "rejected", "added_by_participant",
    "fixed", "fix_planned", "no_fix",
)
INVENTORY_FIELDS = (
    "assumptions_total", "risks_total",
    "mitigations_total", "mitigations_human", "mitigations_planned", "mitigations_implemented",
    "accepted_with_mitigation", "accepted_with_implemented_mitigation",
)
STATE_PART_FIELDS = (
    "participant_code", "task_id", "part", *VULNERABILITY_FIELDS, *INVENTORY_FIELDS,
    "accepted_without_mitigation",
)
STATE_DECISION_FIELDS = (
    "participant_code", "task_id", "part", "approval_id", "actor", "action_type",
    "decision_status", "fix_choice", "decision_seconds",
)
STATE_ACTIONS = ("propose_assumption", "propose_risk", "propose_vulnerability", "mark_resolved", "write_fix")


def read_csv(folder, filename):
    if filename.startswith("v_security_state_") and not (folder / filename).is_file():
        raise FileNotFoundError(f"{folder / filename} is missing; apply the latest migration and rerun export.py")
    with (folder / filename).open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def truth(value):
    return value.strip().lower() == "true"


def index_unique(rows, fields):
    result = {}
    for row in rows:
        key = tuple(row[field] for field in fields)
        if key in result:
            raise ValueError(f"Duplicate {fields} row: {key}")
        result[key] = row
    return result


def eligible_pairs(rows, *, pilots=False):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["participant_code"]].append(row)
    pairs, exclusions = {}, Counter()
    for code, parts in grouped.items():
        is_pilot = code.startswith("X") or any(truth(p["pilot"]) for p in parts)
        if code.startswith("SYN"):
            exclusions["sample_data"] += 1
        elif pilots and not is_pilot:
            exclusions["outside_cohort"] += 1
        elif not pilots and is_pilot:
            exclusions["pilot"] += 1
        elif any(p["participant_status"] == "withdrawn" for p in parts):
            exclusions["withdrawn"] += 1
        elif not pilots and any(p["participant_status"] != "complete" for p in parts):
            exclusions["incomplete"] += 1
        elif len(parts) != 2 or {p["mode"] for p in parts} != {"team", "single"}:
            exclusions["missing_or_duplicate_mode"] += 1
        elif any(not truth(p["submitted"]) for p in parts):
            exclusions["unsubmitted_part"] += 1
        elif {p["part"] for p in parts} != {"1", "2"}:
            exclusions["part_order_mismatch"] += 1
        elif not pilots and len({p["task_id"] for p in parts}) != 2:
            exclusions["same_task_legacy_session"] += 1
        else:
            pairs[code] = {p["mode"]: p for p in parts}
    return pairs, exclusions


def paired_summary(rows, team_key, single_key, stats=None):
    team = [float(row[team_key]) for row in rows]
    single = [float(row[single_key]) for row in rows]
    differences = [a - b for a, b in zip(team, single)]
    result = {
        "n": len(rows),
        "team_median": median(team) if team else None,
        "single_median": median(single) if single else None,
        "mean_paired_difference": mean(differences) if differences else None,
        "team_higher": sum(d > 0 for d in differences),
        "single_higher": sum(d < 0 for d in differences),
        "tied": sum(d == 0 for d in differences),
        "wilcoxon_p_two_sided_exploratory": None,
    }
    if stats is not None and len(rows) >= 5 and any(differences):
        result["wilcoxon_p_two_sided_exploratory"] = float(
            stats.wilcoxon(team, single, alternative="two-sided", zero_method="wilcox").pvalue
        )
    return result


def mcnemar_exact(rows):
    """Exact two-sided paired test for the all-task-tests-passed binary outcome."""
    team_only = sum(row["team_all_passed"] and not row["single_all_passed"] for row in rows)
    single_only = sum(row["single_all_passed"] and not row["team_all_passed"] for row in rows)
    discordant = team_only + single_only
    p = min(1.0, 2 * sum(comb(discordant, i) for i in range(min(team_only, single_only) + 1)) / 2**discordant) if discordant else None
    return {"team_only_passed": team_only, "single_only_passed": single_only,
            "discordant_pairs": discordant, "exact_two_sided_p": p}


def write_csv(path, rows, fields):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    content = stream.getvalue().encode("utf-8")
    if not path.is_file() or path.read_bytes() != content:
        path.write_bytes(content)


def report_header(summary):
    cohort = summary["cohort"]
    lines = ["# Analysis results", ""]
    if cohort == "pilot":
        lines += ["**Pilot data, not final study findings.**", ""]
    return lines


def write_report(path, summary, functional, security=(), combined=()):
    task = summary["task_pass_rate"]
    lines = report_header(summary)
    lines += [
        (f"Paired participants: **{summary['eligible_paired_participants']}**; "
         f"pairs with final task-test results: **{summary['functional_pairs']}**."),
        (f"Starting mode: team **{summary['first_mode_counts'].get('team', 0)}**, "
         f"single **{summary['first_mode_counts'].get('single', 0)}**. "
         "Task allocation and order counts are recorded in `summary.json`."),
        "",
        "## Unit and security tests (v_unit_test_results.csv; paired_parts.csv)",
        "",
        "| Participant | Test type | Session status | Team task | Single task | All tests passed (team) | All tests passed (single) | Team pass rate | Single pass rate |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in functional:
        lines.append(
            f"| {row['participant_code']} | Unit | {row['participant_status']} | {row['team_task_id']} | {row['single_task_id']} | {row['team_all_passed']} | {row['single_all_passed']} "
            f"| {row['team_pass_rate']:.2f} | {row['single_pass_rate']:.2f} |"
        )
    for row in security:
        lines.append(
            f"| {row['participant_code']} | Security | {row['participant_status']} | {row['team_task_id']} | {row['single_task_id']} | {row['team_all_passed']} | {row['single_all_passed']} "
            f"| {row['team_pass_rate']:.2f} | {row['single_pass_rate']:.2f} |"
        )
    for row in combined:
        lines.append(
            f"| {row['participant_code']} | Combined | {row['participant_status']} | {row['team_task_id']} | {row['single_task_id']} | {row['team_all_passed']} | {row['single_all_passed']} "
            f"| {row['team_pass_rate']:.2f} | {row['single_pass_rate']:.2f} |"
        )
    security_rates = summary["security_pass_rate"]
    lines += [
        "",
        (f"Functional tests, median pass rate: team **{task['team_median']}**, single **{task['single_median']}**. "
         f"Team higher for {task['team_higher']} pair(s), single higher for {task['single_higher']}, "
         f"tied for {task['tied']}."),
        (f"Security tests, paired submissions **{len(security)}**; median pass rate: "
         f"team **{security_rates['team_median'] if security else 'Not available'}**, "
         f"single **{security_rates['single_median'] if security else 'Not available'}**. "
         f"All security tests passed: team **{summary['security_passed_all']['team']}**, "
         f"single **{summary['security_passed_all']['single']}**."),
        (f"Security assessments excluded from paired scores: {summary['security_excluded_by_reason']}. "
         "Missing assessments and interrupted or incomplete runs remain unscored."),
        "",
        "| Test group | Mode | Submissions | Tests passed | Total tests | Overall pass rate | Median submission pass rate | All tests passed |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for kind, modes in summary["test_results_by_type"].items():
        for mode, values in modes.items():
            overall = f"{values['pass_rate'] * 100:.1f}%" if values["pass_rate"] is not None else "Unavailable"
            midpoint = f"{values['median_pass_rate'] * 100:.1f}%" if values["median_pass_rate"] is not None else "Unavailable"
            lines.append(
                f"| {kind.title()} | {mode} | {values['submissions']} | {values['passed']} | {values['total']} "
                f"| {overall} | {midpoint} | {values['all_passed']} |"
            )
    lines += [
        "",
        "Combined pass rates use the sum of unit and security tests passed divided by their total test count.",
        "",
        "## Functional results by task (v_unit_test_results.csv; paired_parts.csv)",
        "",
        "| Task | Mode | Attempts | Median pass rate | Passed all tests |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for task_id, modes in summary["functional_by_task"].items():
        for mode, values in modes.items():
            lines.append(f"| {task_id} | {mode} | {values['n']} | {values['median_pass_rate']} | {values['passed_all']} |")
    if not summary["functional_by_task"]:
        lines.append("| No final task tests | | 0 | | |")
    designs = summary["task_design_counts"]
    if designs.get("same_task_legacy") and not designs.get("different_tasks"):
        task_note = "These legacy pilot attempts repeated the same task, so the second attempt may reflect learning."
    else:
        task_note = (
            "Within-participant differences may compare different tasks. Task 2 was chosen by the participant, "
            "so these differences cannot be attributed to the agent mode alone."
        )
    lines += [
        "",
        task_note,
        "",
        "## Activity (v_part_summary.csv; paired_activity.csv)",
        "",
        "| Measure | Paired parts | Team median | Single median | Mean team minus single |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for field, values in summary["activity_by_measure"].items():
        lines.append(f"| {field} | {values['n']} | {values['team_median']} | {values['single_median']} | {values['mean_paired_difference']} |")
    lines += [
        "",
        "## Paired questionnaire answers (v_survey_paired.csv; paired_survey.csv)",
        "",
        "| Item | Paired answers | Team median | Single median |",
        "| --- | ---: | ---: | ---: |",
    ]
    for item, values in summary["survey_by_item"].items():
        lines.append(f"| {item} | {values['n']} | {values['team_median']} | {values['single_median']} |")
    if not summary["survey_by_item"]:
        lines.append("| No paired responses | 0 | — | — |")
    lines += [
        "",
        "## Vulnerabilities and mitigations (Team Mode)",
        "",
        *vulnerability_sections(summary),
        "",
        "## Shared security state (Team Mode)",
        "",
        *state_sections(summary),
        "",
        ("Functional tests measure specified requirements. Hidden security tests exercise selected security properties. "
         "Recorded mitigations are not an independent code assessment. "
         "Questionnaire medians are item responses, not a validated combined scale."),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def vulnerability_sections(summary):
    totals = summary["team_state"]
    inventory = summary["state_inventory_totals"]
    measures = (
        ("Code Reviewer proposals", "proposed_by_reviewer"),
        ("Accepted findings", "accepted"),
        ("Rejected findings", "rejected"),
        ("Developer-added findings", "added_by_participant"),
    )
    lines = [
        "### Finding decisions (v_vulnerability_outcomes.csv; security_state_parts.csv)",
        "",
        "| Measure | Count |",
        "| --- | ---: |",
        *(f"| {label} | {totals[field]} |" for label, field in measures),
        "",
        "### Mitigation linkage (v_vulnerability_outcomes.csv; v_security_state_inventory.csv; security_state_parts.csv)",
        "",
        "| Mitigation status | Count |",
        "| --- | ---: |",
        f"| Accepted findings with a mitigation | {inventory['accepted_with_mitigation']} / {totals['accepted']} |",
        f"| Accepted findings marked fixed | {totals['fixed']} / {totals['accepted']} |",
        f"| Accepted findings with a planned mitigation | {totals['fix_planned']} / {totals['accepted']} |",
        f"| Accepted findings without a mitigation record | {totals['no_fix']} / {totals['accepted']} |",
        f"| Mitigation records added by developer | {inventory['mitigations_human']} |",
        "",
        ("A proposal is not an accepted vulnerability. 'Fixed' and 'implemented' mean the mitigation was recorded "
         "as implemented, not that an independent assessment verified the final code."),
    ]
    return lines


def state_sections(summary):
    inventory = summary["state_inventory_totals"]
    decisions = summary["state_decisions_by_action"]
    lines = [
        "### State inventory (v_vulnerability_outcomes.csv; v_security_state_inventory.csv; security_state_parts.csv)",
        "",
        "| Recorded measure | Count |",
        "| --- | ---: |",
        *(f"| {field} | {inventory[field]} |" for field in (*INVENTORY_FIELDS, "accepted_without_mitigation")),
        "",
        "### Decisions by action (v_security_state_decisions.csv; security_state_decisions.csv)",
        "",
        "| Action | Pending | Approved | Rejected | Suggested | Written | Undone | Median decision seconds |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for action in STATE_ACTIONS:
        values = decisions[action]
        counts = values["statuses"]
        lines.append(
            f"| {action} | {counts.get('pending', 0)} | {counts.get('approved', 0)} "
            f"| {counts.get('rejected', 0)} | {counts.get('suggested', 0)} "
            f"| {counts.get('written', 0)} | {counts.get('undone', 0)} "
            f"| {values['median_decision_seconds'] if values['median_decision_seconds'] is not None else '-'} |"
        )
    lines += [
        "",
        ("Risks are recorded as suggestions without approval. These counts describe recorded state and decisions, "
         "not whether the final code is secure."),
    ]
    return lines


def security_test_pairs(tests, pairs):
    paired, excluded = [], Counter()
    for code, modes in sorted(pairs.items()):
        runs = {mode: tests.get((code, mode)) for mode in ("team", "single")}
        if any(run is None or not run.get("security_tests_total") for run in runs.values()):
            excluded["missing_assessment"] += 1
            continue
        if any(run["task_id"] != modes[mode]["task_id"]
               or run.get("security_task_id", run["task_id"]) != modes[mode]["task_id"]
               for mode, run in runs.items()):
            excluded["task_mismatch"] += 1
            continue
        if len({run.get("security_suite_version") for run in runs.values()}) != 1:
            excluded["suite_version_mismatch"] += 1
            continue
        if any(run.get("security_status") not in ("passed", "failed") or int(run["security_tests_total"]) <= 0
               or not truth(run.get("security_assessment_complete", "False"))
               or any(int(run.get(f"security_tests_{field}") or 0) > 0 for field in ("error", "skipped", "not_run"))
               or int(run["security_tests_passed"]) < 0 or int(run["security_tests_failed"]) < 0
               or int(run["security_tests_passed"]) + int(run["security_tests_failed"]) != int(run["security_tests_total"])
               for run in runs.values()):
            excluded["incomplete_or_error"] += 1
            continue
        row = {"participant_code": code, "participant_status": modes["team"]["participant_status"]}
        for mode, run in runs.items():
            row[f"{mode}_task_id"] = run["task_id"]
            for field in ("total", "passed", "failed"):
                row[f"{mode}_tests_{field}"] = int(run[f"security_tests_{field}"])
            row[f"{mode}_pass_rate"] = row[f"{mode}_tests_passed"] / row[f"{mode}_tests_total"]
            row[f"{mode}_all_passed"] = row[f"{mode}_tests_passed"] == row[f"{mode}_tests_total"]
        paired.append(row)
    return paired, excluded


def combined_test_pairs(tests, functional, security):
    security_by_code = {row["participant_code"]: row for row in security}
    paired, excluded = [], Counter()
    for unit in functional:
        code = unit["participant_code"]
        assessment = security_by_code.get(code)
        if assessment is None:
            excluded["missing_security_pair"] += 1
            continue
        runs = {mode: tests[(code, mode)] for mode in ("team", "single")}
        if any(not truth(run.get("combined_assessment_complete", "False"))
               or int(run.get("combined_tests_total") or 0) <= 0 for run in runs.values()):
            excluded["incomplete_combined_result"] += 1
            continue
        row = {field: unit[field] for field in ("participant_code", "participant_status", "team_task_id", "single_task_id")}
        valid = True
        for mode, run in runs.items():
            for field in ("total", "passed", "failed"):
                count = int(run[f"combined_tests_{field}"])
                if count != unit[f"{mode}_tests_{field}"] + assessment[f"{mode}_tests_{field}"]:
                    valid = False
                row[f"{mode}_tests_{field}"] = count
            row[f"{mode}_pass_rate"] = row[f"{mode}_tests_passed"] / row[f"{mode}_tests_total"]
            row[f"{mode}_all_passed"] = row[f"{mode}_tests_passed"] == row[f"{mode}_tests_total"]
        if valid:
            paired.append(row)
        else:
            excluded["inconsistent_combined_counts"] += 1
    return paired, excluded


def test_totals(rows):
    result = {}
    for mode in ("team", "single"):
        passed = sum(row[f"{mode}_tests_passed"] for row in rows)
        total = sum(row[f"{mode}_tests_total"] for row in rows)
        result[mode] = {
            "submissions": len(rows), "passed": passed, "total": total,
            "pass_rate": passed / total if total else None,
            "median_pass_rate": median(row[f"{mode}_pass_rate"] for row in rows) if rows else None,
            "all_passed": sum(row[f"{mode}_all_passed"] for row in rows),
        }
    return result


def analyse(source: Path, destination: Path, stats=None, *, pilots=False):
    parts = read_csv(source, "v_part_summary.csv")
    tests = index_unique(read_csv(source, "v_unit_test_results.csv"), ("participant_code", "mode"))
    survey = read_csv(source, "v_survey_paired.csv")
    all_survey = read_csv(source, "v_survey.csv")
    vulnerabilities = index_unique(read_csv(source, "v_vulnerability_outcomes.csv"), ("participant_code", "mode"))
    inventory = index_unique(read_csv(source, "v_security_state_inventory.csv"), ("participant_code", "mode"))
    approvals = read_csv(source, "v_security_state_decisions.csv")
    pairs, exclusions = eligible_pairs(parts, pilots=pilots)
    security, missing_security = security_test_pairs(tests, pairs)

    activity = []
    for code, modes in sorted(pairs.items()):
        row = {"participant_code": code, "participant_status": modes["team"]["participant_status"],
               "team_task_id": modes["team"]["task_id"], "single_task_id": modes["single"]["task_id"],
               "first_mode": "team" if modes["team"]["part"] == "1" else "single",
               "first_task_id": next(p["task_id"] for p in modes.values() if p["part"] == "1")}
        for mode in ("team", "single"):
            for field in ("reviews", "test_runs", "messages_typed", "seconds_on_task"):
                row[f"{mode}_{field}"] = modes[mode][field]
        activity.append(row)

    functional, missing_tests = [], Counter()
    for code, modes in sorted(pairs.items()):
        team_test, single_test = tests.get((code, "team")), tests.get((code, "single"))
        if team_test is None or single_test is None:
            missing_tests["missing_test_export"] += 1
            continue
        if any(int(t["task_tests"] or 0) == 0 or int(t["task_tests_not_run"] or 0) > 0 for t in (team_test, single_test)):
            missing_tests["missing_or_unrun_task_tests"] += 1
            continue
        if any(t["task_id"] != modes[m]["task_id"] for m, t in (("team", team_test), ("single", single_test))):
            missing_tests["task_mismatch"] += 1
            continue
        rates = {m: int(t["task_tests_passed"]) / int(t["task_tests"]) for m, t in (("team", team_test), ("single", single_test))}
        row = {"participant_code": code, "participant_status": modes["team"]["participant_status"],
               "team_task_id": modes["team"]["task_id"], "single_task_id": modes["single"]["task_id"],
               "first_mode": "team" if modes["team"]["part"] == "1" else "single",
               "first_task_id": next(p["task_id"] for p in modes.values() if p["part"] == "1"),
               "team_pass_rate": rates["team"], "single_pass_rate": rates["single"],
               "team_all_passed": truth(team_test["all_task_tests_passed"]),
               "single_all_passed": truth(single_test["all_task_tests_passed"])}
        for mode in ("team", "single"):
            test = tests[(code, mode)]
            row[f"{mode}_tests_total"] = int(test["task_tests"])
            row[f"{mode}_tests_passed"] = int(test["task_tests_passed"])
            row[f"{mode}_tests_failed"] = int(test.get("task_tests_failed") or (int(test["task_tests"]) - int(test["task_tests_passed"])))
            for field in ("reviews", "test_runs", "seconds_on_task"):
                row[f"{mode}_{field}"] = modes[mode][field]
        functional.append(row)

    combined, missing_combined = combined_test_pairs(tests, functional, security)
    test_groups = {"unit": functional, "security": security, "combined": combined}

    paired_survey, seen = [], set()
    for answer in survey:
        code, item = answer["participant_code"], answer["item"]
        if code not in pairs or not answer["team_score"] or not answer["single_score"]:
            continue
        if (code, item) in seen:
            raise ValueError(f"Duplicate paired questionnaire answer: {(code, item)}")
        seen.add((code, item))
        team, single = int(answer["team_score"]), int(answer["single_score"])
        paired_survey.append({"participant_code": code, "item": item,
                              "team_answer": answer["team_answer"], "single_answer": answer["single_answer"],
                              "team_score": team, "single_score": single, "team_minus_single": team - single})
    paired_survey.sort(key=lambda row: (row["item"], row["participant_code"]))
    by_item = defaultdict(list)
    for row in paired_survey:
        by_item[row["item"]].append(row)

    team_only = defaultdict(list)
    for answer in all_survey:
        if (answer["participant_code"] in pairs and answer["condition"] == "team"
                and (answer["item"].startswith("state_") or answer["item"] == "specialist_role_clarity")):
            team_only[answer["item"]].append(answer)

    state_parts = []
    for code, modes in sorted(pairs.items()):
        finding = vulnerabilities.get((code, "team"))
        state = inventory.get((code, "team"))
        if (finding is None or state is None or not truth(finding["submitted"])
                or not truth(state["submitted"])
                or finding["task_id"] != modes["team"]["task_id"]
                or state["task_id"] != modes["team"]["task_id"]
                or finding["part"] != modes["team"]["part"]
                or state["part"] != modes["team"]["part"]):
            raise ValueError(f"Missing or mismatched team security-state export for {code}; rerun export.py")
        row = {"participant_code": code, "task_id": modes["team"]["task_id"], "part": modes["team"]["part"]}
        row.update({field: int(finding[field] or 0) for field in VULNERABILITY_FIELDS})
        row.update({field: int(state[field] or 0) for field in INVENTORY_FIELDS})
        row["accepted_without_mitigation"] = row["accepted"] - row["accepted_with_mitigation"]
        if (row["accepted_without_mitigation"] < 0
                or row["accepted_with_implemented_mitigation"] > row["accepted_with_mitigation"]
                or row["fixed"] != row["accepted_with_implemented_mitigation"]
                or row["no_fix"] != row["accepted_without_mitigation"]
                or row["mitigations_planned"] + row["mitigations_implemented"] != row["mitigations_total"]):
            raise ValueError(f"Inconsistent team security-state counts for {code}")
        state_parts.append(row)

    state_decisions = []
    seen_approvals = set()
    for approval in approvals:
        code = approval["participant_code"]
        if code not in pairs:
            continue
        if (approval["mode"] != "team" or not truth(approval["submitted"])
                or approval["task_id"] != pairs[code]["team"]["task_id"]
                or approval["part"] != pairs[code]["team"]["part"]):
            raise ValueError(f"Mismatched team security-state decision for {code}")
        if approval["action_type"] not in STATE_ACTIONS:
            raise ValueError(f"Unknown security-state action: {approval['action_type']}")
        if approval["decision_status"] not in {"pending", "approved", "rejected", "suggested", "written", "undone"}:
            raise ValueError(f"Unknown security-state decision status: {approval['decision_status']}")
        if approval["approval_id"] in seen_approvals:
            raise ValueError(f"Duplicate security-state decision: {approval['approval_id']}")
        seen_approvals.add(approval["approval_id"])
        state_decisions.append({field: approval[field] for field in STATE_DECISION_FIELDS})
    state_decisions.sort(key=lambda row: (row["participant_code"], int(row["approval_id"])))
    decisions_by_action = {}
    for action in STATE_ACTIONS:
        rows = [row for row in state_decisions if row["action_type"] == action]
        seconds = [float(row["decision_seconds"]) for row in rows
                   if row["decision_status"] in {"approved", "rejected"} and row["decision_seconds"]]
        decisions_by_action[action] = {
            "statuses": dict(Counter(row["decision_status"] for row in rows)),
            "median_decision_seconds": median(seconds) if seconds else None,
        }
    fix_choices = Counter(
        row["fix_choice"] or "not_recorded" for row in state_decisions
        if row["action_type"] == "propose_vulnerability" and row["decision_status"] == "approved"
    )
    by_task = defaultdict(lambda: defaultdict(list))
    for row in functional:
        for mode in ("team", "single"):
            by_task[row[f"{mode}_task_id"]][mode].append(row)
    legacy_only = bool(pairs) and all(p["team"]["task_id"] == p["single"]["task_id"] for p in pairs.values())
    result = {
        "cohort": "pilot" if pilots else "study",
        "pilot_sample_only": pilots,
        "participants_in_export": len({p["participant_code"] for p in parts}),
        "eligible_paired_participants": len(pairs),
        "excluded_by_reason": dict(exclusions),
        "included_status_counts": dict(Counter(p["team"]["participant_status"] for p in pairs.values())),
        "functional_pairs": len(functional),
        "security_test_pairs": len(security),
        "security_excluded_by_reason": dict(missing_security),
        "security_pass_rate": paired_summary(security, "team_pass_rate", "single_pass_rate"),
        "security_passed_all": {mode: sum(row[f"{mode}_all_passed"] for row in security) for mode in ("team", "single")},
        "combined_test_pairs": len(combined),
        "combined_excluded_by_reason": dict(missing_combined),
        "combined_pass_rate": paired_summary(combined, "team_pass_rate", "single_pass_rate"),
        "combined_passed_all": {mode: sum(row[f"{mode}_all_passed"] for row in combined) for mode in ("team", "single")},
        "test_results_by_type": {kind: test_totals(rows) for kind, rows in test_groups.items()},
        "functional_excluded_by_reason": dict(missing_tests),
        "first_mode_counts": dict(Counter("team" if p["team"]["part"] == "1" else "single" for p in pairs.values())),
        "task_assignment_counts": {
            mode: dict(Counter(p[mode]["task_id"] for p in pairs.values())) for mode in ("team", "single")
        },
        "task_order_counts": dict(Counter(
            " -> ".join(next(row["task_id"] for row in p.values() if row["part"] == str(part)) for part in (1, 2))
            for p in pairs.values()
        )),
        "task_mode_sequence_counts": dict(Counter(
            " -> ".join(
                f"{row['task_id']}/{row['mode']}" for part in (1, 2)
                for row in p.values() if row["part"] == str(part)
            ) for p in pairs.values()
        )),
        "task_design_counts": dict(Counter(
            "same_task_legacy" if p["team"]["task_id"] == p["single"]["task_id"] else "different_tasks"
            for p in pairs.values()
        )),
        "task_pass_rate": paired_summary(functional, "team_pass_rate", "single_pass_rate", stats if legacy_only else None),
        "passed_all_task_tests": {m: sum(r[f"{m}_all_passed"] for r in functional) for m in ("team", "single")},
        "all_task_tests_passed_paired_test": mcnemar_exact(functional) if legacy_only else None,
        "functional_by_task": {
            task_id: {
                mode: {"n": len(rows), "median_pass_rate": median(r[f"{mode}_pass_rate"] for r in rows),
                       "passed_all": sum(r[f"{mode}_all_passed"] for r in rows)}
                for mode, rows in modes.items()
            } for task_id, modes in sorted(by_task.items())
        },
        "activity_by_measure": {
            field: paired_summary(
                [row for row in activity if row[f"team_{field}"] != "" and row[f"single_{field}"] != ""],
                f"team_{field}", f"single_{field}"
            ) for field in ("reviews", "test_runs", "messages_typed", "seconds_on_task")
        },
        "survey_by_item": {item: paired_summary(rows, "team_score", "single_score", stats if legacy_only else None) for item, rows in sorted(by_item.items())},
        "team_only_survey": {
            item: {"answers": dict(Counter(row["value"] for row in rows if row["value"])),
                   "missing_or_not_applicable": sum(not row["score"] for row in rows)}
            for item, rows in sorted(team_only.items())
        },
        "team_state": {field: sum(row[field] for row in state_parts) for field in VULNERABILITY_FIELDS},
        "state_inventory_totals": {field: sum(row[field] for row in state_parts)
                                   for field in (*INVENTORY_FIELDS, "accepted_without_mitigation")},
        "state_decisions_by_action": decisions_by_action,
        "fix_choice_counts": {choice: fix_choices[choice] for choice in ("reviewer", "developer", "not_recorded")},
        "interpretation": (
            ("PILOT SAMPLE ONLY: illustrative output, not final study evidence. " if pilots else "")
            + "Task tests are not a vulnerability audit. Team state is descriptive; fixed means a recorded mitigation. "
            + ("Legacy same-task attempts may reflect learning." if legacy_only else
               "Participant-selected different tasks confound mode comparisons; no mode-effect p-values are calculated for them.")
        ),
    }
    destination.mkdir(parents=True, exist_ok=True)
    write_csv(destination / "paired_activity.csv", activity,
              ["participant_code", "participant_status", "team_task_id", "single_task_id", "first_mode", "first_task_id", *(
                  f"{mode}_{field}" for mode in ("team", "single")
                  for field in ("reviews", "test_runs", "messages_typed", "seconds_on_task"))])
    part_fields = ["participant_code", "participant_status", "team_task_id", "single_task_id", "first_mode", "first_task_id",
                   "team_pass_rate", "single_pass_rate", "team_all_passed", "single_all_passed",
                   "team_reviews", "team_test_runs", "team_seconds_on_task", "single_reviews", "single_test_runs", "single_seconds_on_task"]
    group_indexes = {kind: {row["participant_code"]: row for row in rows} for kind, rows in test_groups.items()}
    paired_parts = []
    for context in activity:
        row = {field: context.get(field, "") for field in part_fields}
        for kind, indexed in group_indexes.items():
            scores = indexed.get(context["participant_code"], {})
            for mode in ("team", "single"):
                prefix = mode if kind == "unit" else f"{mode}_{kind}"
                for field in ("pass_rate", "all_passed"):
                    row[f"{prefix}_{field}"] = scores.get(f"{mode}_{field}", "")
                for field in ("total", "passed", "failed"):
                    row[f"{mode}_{kind}_tests_{field}"] = scores.get(f"{mode}_tests_{field}", "")
        paired_parts.append(row)
    for kind in test_groups:
        for mode in ("team", "single"):
            if kind != "unit":
                part_fields.extend([f"{mode}_{kind}_pass_rate", f"{mode}_{kind}_all_passed"])
            part_fields.extend(f"{mode}_{kind}_tests_{field}" for field in ("total", "passed", "failed"))
    write_csv(destination / "paired_parts.csv", paired_parts, part_fields)
    write_csv(destination / "paired_survey.csv", paired_survey,
              ["participant_code", "item", "team_answer", "single_answer", "team_score", "single_score", "team_minus_single"])
    write_csv(destination / "security_state_parts.csv", state_parts, STATE_PART_FIELDS)
    write_csv(destination / "security_state_decisions.csv", state_decisions, STATE_DECISION_FIELDS)
    (destination / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_report(destination / "report.md", result, functional, security, combined)
    for old_name in ("README.md", "vulnerabilities_and_mitigations.md", "security_state.md", "paired_task_tests.csv"):
        (destination / old_name).unlink(missing_ok=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "results")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pilots", action="store_true", help="analyse pilot pairs only; include incomplete pilots with both task parts submitted")
    args = parser.parse_args()
    output = args.output or ROOT / "results" / "analysis" / ("pilot" if args.pilots else "study")
    try:
        stats = import_module("scipy.stats")
    except ImportError:
        stats = None
    summary = analyse(args.input, output, stats, pilots=args.pilots)
    if stats is None and summary["task_design_counts"].get("same_task_legacy"):
        print("SciPy unavailable: legacy same-task pilots have descriptive results only.")
    print(f"Cohort: {summary['cohort']}")
    print(f"Eligible participant pairs: {summary['eligible_paired_participants']}")
    print(f"Functional pairs: {summary['functional_pairs']}")
    print(f"Results: {output}")
