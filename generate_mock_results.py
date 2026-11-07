"""Create reproducible, fabricated CSVs for trying the analysis workflow.

Only results/synthetic/ is written. Real participant exports and the database are untouched.
Run `uv run python export.py` once if results/*.csv headers are missing.
"""

import csv
import json
import random
from itertools import permutations
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
OUTPUT = RESULTS / "synthetic"
SEED = 20261107
TASKS = "ABCDE"
COMMON = {"participant_status": "complete", "pilot": False, "submitted": True}

# (reviewer proposals, accepted, rejected, human additions, implemented fixes, planned fixes)
FINDINGS = [
    (0, 0, 0, 0, 0, 0),  # clean review
    (1, 1, 0, 0, 1, 0),
    (1, 1, 0, 0, 0, 1),
    (1, 1, 0, 0, 0, 0),
    (1, 0, 1, 0, 0, 0),  # rejected finding
    (2, 1, 1, 0, 1, 0),
    (2, 2, 0, 0, 1, 0),
    (1, 2, 0, 1, 1, 1),  # includes a human-added finding
]
# Three provided functional tests per task; balanced outcomes include team higher, single higher and ties.
TEST_OUTCOMES = [(3, 3), (3, 2), (2, 3), (2, 2), (3, 1), (1, 3), (1, 2), (2, 1), (2, 0), (0, 2)]


def write_view(name: str, rows: list[dict]) -> None:
    source = RESULTS / name
    if not source.is_file():
        raise FileNotFoundError(f"{source} is missing; run `uv run python export.py` to create the headers first")
    with source.open(newline="", encoding="utf-8-sig") as stream:
        columns = next(csv.reader(stream))
    for row in rows:
        if set(row) != set(columns):
            raise ValueError(f"{name} columns changed: missing={set(columns) - set(row)}, extra={set(row) - set(columns)}")
    with (OUTPUT / name).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def response(question: dict, mode: str, passed: dict[str, int], rng: random.Random) -> tuple[str, str, str]:
    if question["type"] == "text" or rng.random() < 0.045:
        return "", "", ""
    options = question.get("options", [])
    if "Not applicable" in options and rng.random() < 0.08:
        return "Not applicable", "", ""
    if question["type"] == "choice":
        ordered = [option for option in options if option != "Not applicable"]
        key = question["key"]
        if key == "functional_confidence":
            score = max(1, min(len(ordered), 1 + passed[mode] + rng.choice((-1, 0, 0, 1))))
        elif key == "security_confidence":
            score = max(1, min(len(ordered), 2 + passed[mode] // 2 + rng.choice((-1, 0, 0, 1))))
        else:
            score = rng.randint(1, len(ordered))
        value = ordered[score - 1]
    else:
        scale = question["scale"]
        score = rng.randint(scale["min"], scale["max"])
        value = str(score)
    scored = (question["scale"]["min"] + question["scale"]["max"] - score
              if question.get("reverse_scored") and question.get("scale") else
              len(ordered) + 1 - score if question.get("reverse_scored") else score)
    return value, str(score), str(scored)


def main() -> None:
    rng = random.Random(SEED)
    questionnaire = json.loads((ROOT / "content" / "questionnaire.json").read_text(encoding="utf-8"))
    questions = [(section, question) for section in questionnaire["sections"] for question in section["questions"]]
    conditions = {"each_mode": ("team", "single"), "team": ("team",), "once": ("none",)}
    assignments = [(first, second, first_mode) for first, second in permutations(TASKS, 2)
                   for first_mode in ("team", "single")]
    findings = FINDINGS * 5
    outcomes = TEST_OUTCOMES * 4
    rng.shuffle(findings)
    rng.shuffle(outcomes)

    rows: dict[str, list[dict]] = {name: [] for name in (
        "survey.csv", "v_part_summary.csv", "v_vulnerability_outcomes.csv", "v_unit_test_results.csv",
        "v_survey.csv", "v_survey_paired.csv",
    )}
    for index, (first_task, second_task, first_mode) in enumerate(assignments):
        code = f"SYN{index + 1:03d}"
        second_mode = "single" if first_mode == "team" else "team"
        parts = [(1, first_task, first_mode), (2, second_task, second_mode)]
        passed = dict(zip(("team", "single"), outcomes[index]))
        proposed, accepted, rejected, human, fixed, planned = findings[index]
        no_fix = accepted - fixed - planned
        assert no_fix >= 0 and proposed >= accepted - human + rejected

        for part, task_id, mode in parts:
            result = passed[mode]
            base = {"participant_code": code, **COMMON, "task_id": task_id, "part": part, "mode": mode}
            own_tests = rng.choice((0, 0, 0, 1, 2))
            own_passed = rng.randint(0, own_tests)
            tests = {**base, "task_tests": 3, "task_tests_passed": result, "task_tests_failed": 3 - result,
                     "task_tests_not_run": 0, "task_pass_rate": f"{result / 3:.2f}",
                     "all_task_tests_passed": result == 3, "own_tests": own_tests, "own_tests_passed": own_passed}
            rows["v_unit_test_results.csv"].append(tests)
            approved = (accepted - human + rng.randint(0, 2)) if mode == "team" else rng.randint(0, 2)
            declined = (rejected + rng.randint(0, 1)) if mode == "team" else rng.randint(0, 1)
            rows["v_part_summary.csv"].append({
                **base, "seconds_on_task": rng.randint(540, 4200), "reviews": rng.randint(1, 4),
                "test_runs": rng.randint(1, 5), "messages_typed": rng.randint(1, 7),
                "proposals_approved": approved, "proposals_rejected": declined, "proposals_undecided": 0,
                "avg_decision_seconds": f"{rng.uniform(5, 90):.1f}" if approved + declined else "",
                "risks": rng.randint(0, 4) if mode == "team" else 0,
                "task_tests": tests["task_tests"], "task_tests_passed": result, "task_tests_failed": 3 - result,
                "task_pass_rate": tests["task_pass_rate"], "all_task_tests_passed": tests["all_task_tests_passed"],
                "vulnerabilities_accepted": accepted if mode == "team" else "",
                "vulnerabilities_rejected": rejected if mode == "team" else "",
                "vulnerabilities_fixed": fixed if mode == "team" else "",
            })
            if mode == "team":
                rows["v_vulnerability_outcomes.csv"].append({
                    **base, "proposed_by_reviewer": proposed, "undecided": 0, "accepted": accepted,
                    "rejected": rejected, "added_by_participant": human, "fixed": fixed,
                    "fix_planned": planned, "no_fix": no_fix,
                })

        answers: dict[tuple[str, str], tuple[str, str, str]] = {}
        for section, question in questions:
            for condition in conditions[section["asked_for"]]:
                value, value_num, score = response(question, condition, passed, rng)
                answers[(condition, question["key"])] = value, value_num, score
                rows["v_survey.csv"].append({
                    "participant_code": code, "participant_status": "complete", "pilot": False,
                    "condition": condition, "number": question["number"], "item": question["key"],
                    "section": section["title"], "type": question["type"], "value": value,
                    "value_num": value_num, "score": score,
                })
            if section["asked_for"] == "each_mode":
                team_answer, _, team_score = answers[("team", question["key"])]
                single_answer, _, single_score = answers[("single", question["key"])]
                rows["v_survey_paired.csv"].append({
                    "participant_code": code, "participant_status": "complete", "pilot": False,
                    "number": question["number"], "item": question["key"],
                    "team_answer": team_answer, "single_answer": single_answer,
                    "team_score": team_score, "single_score": single_score,
                    "team_minus_single": int(team_score) - int(single_score) if team_score and single_score else "",
                })
        wide = {"participant": code, "first_mode": first_mode}
        wide.update({f"{item}_{condition}" if condition != "none" else item: value
                     for (condition, item), (value, _, _) in answers.items()})
        rows["survey.csv"].append(wide)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in rows.items():
        write_view(name, data)
        print(f"Wrote {len(data)} synthetic row(s) to {OUTPUT / name}")
    (OUTPUT / "README.md").write_text(
        "# Synthetic results for analysis rehearsal\n\n"
        "These records are fabricated. They are not participant responses, observations, pilot data or evidence "
        "that either AI mode performs better. Never combine them with results/*.csv or report their figures as study findings.\n\n"
        f"The generator uses seed {SEED} and creates {len(assignments)} SYN-prefixed mock participants. "
        "Every ordered pair of the five tasks appears with each mode first. All mock parts are marked complete "
        "so the existing analysis can exercise its paired-data path. Functional tests, finding decisions, "
        "mitigation states and optional questionnaire answers vary across records. Open feedback is blank.\n\n"
        "Regenerate with `uv run python generate_mock_results.py`. The script reads only the headers of the "
        "current real exports and writes only inside this directory.\n\n"
        "Analyze with `uv run python analyze_results.py --input results/synthetic "
        "--output results/synthetic/analysis --synthetic`. Different tasks are assigned to each mode, "
        "so paired differences are descriptive and do not isolate a mode effect.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
