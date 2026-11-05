"""Analyse completed participant pairs from export.py's CSV files.

Run: uv run --with scipy python analyze_results.py
Results go to results/analysis. This does not assess final-code vulnerabilities.
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


def eligible_pairs(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["participant_code"]].append(row)
    pairs, exclusions = {}, Counter()
    for code, parts in grouped.items():
        if code.startswith("X") or any(truth(p["pilot"]) for p in parts):
            exclusions["pilot"] += 1
        elif any(p["participant_status"] == "withdrawn" for p in parts):
            exclusions["withdrawn"] += 1
        elif any(p["participant_status"] != "complete" for p in parts):
            exclusions["incomplete"] += 1
        elif len(parts) != 2 or {p["mode"] for p in parts} != {"team", "single"}:
            exclusions["missing_or_duplicate_mode"] += 1
        elif any(not truth(p["submitted"]) for p in parts):
            exclusions["unsubmitted_part"] += 1
        elif len({p["task_id"] for p in parts}) != 1 or {p["part"] for p in parts} != {"1", "2"}:
            exclusions["task_or_order_mismatch"] += 1
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


def analyse(source: Path, destination: Path, stats=None):
    parts = read_csv(source, "v_part_summary.csv")
    tests = index_unique(read_csv(source, "v_unit_test_results.csv"), ("participant_code", "mode"))
    survey = read_csv(source, "v_survey_paired.csv")
    all_survey = read_csv(source, "v_survey.csv")
    vulnerabilities = read_csv(source, "v_vulnerability_outcomes.csv")
    pairs, exclusions = eligible_pairs(parts)

    activity = []
    for code, modes in sorted(pairs.items()):
        row = {"participant_code": code, "task_id": modes["team"]["task_id"],
               "first_mode": "team" if modes["team"]["part"] == "1" else "single"}
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
        row = {"participant_code": code, "task_id": modes["team"]["task_id"],
               "first_mode": "team" if modes["team"]["part"] == "1" else "single",
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
    result = {
        "participants_in_export": len({p["participant_code"] for p in parts}),
        "eligible_paired_participants": len(pairs),
        "excluded_by_reason": dict(exclusions),
        "functional_pairs": len(functional),
        "functional_excluded_by_reason": dict(missing_tests),
        "first_mode_counts": dict(Counter("team" if p["team"]["part"] == "1" else "single" for p in pairs.values())),
        "task_counts": dict(Counter(p["team"]["task_id"] for p in pairs.values())),
        "task_pass_rate": paired_summary(functional, "team_pass_rate", "single_pass_rate", stats),
        "passed_all_task_tests": {m: sum(r[f"{m}_all_passed"] for r in functional) for m in ("team", "single")},
        "all_task_tests_passed_paired_test": mcnemar_exact(functional),
        "activity_by_measure": {
            field: paired_summary(
                [row for row in activity if row[f"team_{field}"] != "" and row[f"single_{field}"] != ""],
                f"team_{field}", f"single_{field}"
            ) for field in ("reviews", "test_runs", "messages_typed", "seconds_on_task")
        },
        "survey_by_item": {item: paired_summary(rows, "team_score", "single_score", stats) for item, rows in sorted(by_item.items())},
        "team_only_survey": {
            item: {"answers": dict(Counter(row["value"] for row in rows if row["value"])),
                   "missing_or_not_applicable": sum(not row["score"] for row in rows)}
            for item, rows in sorted(team_only.items())
        },
        "team_state": {field: sum(int(row[field] or 0) for row in team_state)
                       for field in ("proposed_by_reviewer", "accepted", "rejected", "fixed", "fix_planned", "no_fix")},
        "interpretation": "Task tests are not a vulnerability audit. Team state is descriptive; fixed means a recorded mitigation. Survey p-values are exploratory and unadjusted.",
    }
    destination.mkdir(parents=True, exist_ok=True)
    write_csv(destination / "paired_activity.csv", activity,
              ["participant_code", "task_id", "first_mode", *(
                  f"{mode}_{field}" for mode in ("team", "single")
                  for field in ("reviews", "test_runs", "messages_typed", "seconds_on_task"))])
    write_csv(destination / "paired_parts.csv", functional,
              ["participant_code", "task_id", "first_mode", "team_pass_rate", "single_pass_rate",
               "team_all_passed", "single_all_passed", "team_reviews", "team_test_runs", "team_seconds_on_task",
               "single_reviews", "single_test_runs", "single_seconds_on_task"])
    write_csv(destination / "paired_survey.csv", paired_survey,
              ["participant_code", "item", "team_answer", "single_answer", "team_score", "single_score", "team_minus_single"])
    (destination / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "results")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "analysis")
    args = parser.parse_args()
    try:
        stats = import_module("scipy.stats")
    except ImportError:
        stats = None
        print("SciPy unavailable: writing descriptive results without Wilcoxon p-values.")
    summary = analyse(args.input, args.output, stats)
    print(f"Eligible participant pairs: {summary['eligible_paired_participants']}")
    print(f"Functional pairs: {summary['functional_pairs']}")
    print(f"Results: {args.output}")
