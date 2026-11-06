"""Describe two-task participant pairs from export.py's CSV files.

Run: uv run python analyze_results.py
Results go to results/analysis. Task 2 is participant-selected, so mode effects are not isolated.
"""

import argparse
import csv
import json
from collections import Counter, defaultdict
from importlib import import_module
from math import comb
from pathlib import Path
from statistics import mean, median

ROOT = Path(__file__).resolve().parent


def read_csv(folder, filename):
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
        if pilots and not is_pilot:
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
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_report(path, summary, functional):
    cohort = summary["cohort"]
    title = "Pilot sample analysis" if cohort == "pilot" else "Study analysis"
    task = summary["task_pass_rate"]
    lines = [f"# {title}", ""]
    if cohort == "pilot":
        lines += ["**Illustrative pilot data only. Do not report these numbers as final study findings.**", ""]
    lines += [
        (f"Paired participants: **{summary['eligible_paired_participants']}**; "
         f"pairs with final task-test results: **{summary['functional_pairs']}**."),
        f"Included session statuses: {summary['included_status_counts']}.",
        f"First mode counts: {summary['first_mode_counts']}. Task assignments: {summary['task_assignment_counts']}.",
        f"Task order counts: {summary['task_order_counts']}.",
        f"Task and mode sequences: {summary['task_mode_sequence_counts']}.",
        "",
        "## Provided task tests",
        "",
        "| Participant | Session status | Team task | Single task | Team passed | Single passed | Team pass rate | Single pass rate |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in functional:
        lines.append(
            f"| {row['participant_code']} | {row['participant_status']} | {row['team_task_id']} | {row['single_task_id']} | {row['team_all_passed']} | {row['single_all_passed']} "
            f"| {row['team_pass_rate']:.2f} | {row['single_pass_rate']:.2f} |"
        )
    lines += [
        "",
        (f"Across assigned tasks, median pass rate: team **{task['team_median']}**, single **{task['single_median']}**. "
         f"Team higher for {task['team_higher']} pair(s), single higher for {task['single_higher']}, "
         f"tied for {task['tied']}."),
        "",
        "## Functional results by task",
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
        "## Paired questionnaire answers",
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
        "## Team security-state records",
        "",
        "| Recorded measure | Count |",
        "| --- | ---: |",
        *(f"| {field} | {count} |" for field, count in summary["team_state"].items()),
        "",
        ("Task tests measure specified requirements, not absence of vulnerabilities. "
         "Recorded mitigations are not an independent code assessment. "
         "Questionnaire medians are item responses, not a validated combined scale."),
    ]
    if cohort == "pilot":
        lines += ["", "This pilot sample is too small for conclusions about which mode performs better."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def analyse(source: Path, destination: Path, stats=None, *, pilots=False):
    parts = read_csv(source, "v_part_summary.csv")
    tests = index_unique(read_csv(source, "v_unit_test_results.csv"), ("participant_code", "mode"))
    survey = read_csv(source, "v_survey_paired.csv")
    all_survey = read_csv(source, "v_survey.csv")
    vulnerabilities = read_csv(source, "v_vulnerability_outcomes.csv")
    pairs, exclusions = eligible_pairs(parts, pilots=pilots)

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
            for field in ("reviews", "test_runs", "seconds_on_task"):
                row[f"{mode}_{field}"] = modes[mode][field]
        functional.append(row)

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

    team_state = [row for row in vulnerabilities if row["participant_code"] in pairs and row["mode"] == "team" and truth(row["submitted"])]
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
        "team_state": {field: sum(int(row[field] or 0) for row in team_state)
                       for field in ("proposed_by_reviewer", "accepted", "rejected", "fixed", "fix_planned", "no_fix")},
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
    write_csv(destination / "paired_parts.csv", functional,
              ["participant_code", "participant_status", "team_task_id", "single_task_id", "first_mode", "first_task_id", "team_pass_rate", "single_pass_rate",
               "team_all_passed", "single_all_passed", "team_reviews", "team_test_runs", "team_seconds_on_task",
               "single_reviews", "single_test_runs", "single_seconds_on_task"])
    write_csv(destination / "paired_survey.csv", paired_survey,
              ["participant_code", "item", "team_answer", "single_answer", "team_score", "single_score", "team_minus_single"])
    (destination / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_report(destination / "report.md", result, functional)
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
