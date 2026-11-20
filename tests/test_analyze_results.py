import csv
from types import SimpleNamespace

import pytest

import analyze_results


def write_rows(folder, name, rows):
    with (folder / name).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_analysis_pairs_only_completed_non_pilot_parts_and_uses_final_tests(tmp_path):
    parts = [
        {"participant_code": code, "participant_status": status, "pilot": str(pilot),
         "task_id": "B" if code == "P01" and mode == "team" else "A", "part": str(part), "mode": mode, "submitted": "True",
         "reviews": "2", "test_runs": "1", "messages_typed": "3", "seconds_on_task": "100"}
        for code, status, pilot, part, mode in [
            ("P01", "complete", False, 1, "single"), ("P01", "complete", False, 2, "team"),
            ("X01", "complete", True, 1, "team"), ("X01", "complete", True, 2, "single"),
            ("P02", "incomplete", False, 1, "team"),
        ]
    ]
    tests = [
        {"participant_code": "P01", "mode": mode, "task_id": "B" if mode == "team" else "A", "task_tests": "3",
         "task_tests_passed": passed, "task_tests_not_run": "0", "all_task_tests_passed": all_passed}
        for mode, passed, all_passed in [("team", "3", "True"), ("single", "2", "False")]
    ]
    survey = [{"participant_code": code, "item": "security_confidence", "team_score": "4",
               "single_score": "2", "team_answer": "Very confident", "single_answer": "Slightly confident"}
              for code in ("P01", "X01")]
    all_survey = [{"participant_code": "P01", "condition": "team", "item": "state_status_tracking",
                   "value": "Agree", "score": "4"}]
    findings = [{"participant_code": "P01", "task_id": "B", "part": "2", "mode": "team", "submitted": "True",
                 "proposed_by_reviewer": "2", "undecided": "0", "accepted": "1", "rejected": "1",
                 "added_by_participant": "0", "fixed": "0", "fix_planned": "1", "no_fix": "0"}]
    inventory = [{"participant_code": "P01", "task_id": "B", "part": "2", "mode": "team", "submitted": "True",
                  "assumptions_total": "2", "risks_total": "2",
                  "mitigations_total": "1", "mitigations_human": "1", "mitigations_planned": "1",
                  "mitigations_implemented": "0", "accepted_with_mitigation": "1",
                  "accepted_with_implemented_mitigation": "0"}]
    decisions = [
        {"participant_code": "P01", "task_id": "B", "part": "2", "mode": "team", "submitted": "True",
         "approval_id": str(index), "actor": "reviewer", "action_type": action,
         "decision_status": status, "fix_choice": "developer" if action == "propose_vulnerability" and status == "approved" else "",
         "decision_seconds": seconds}
        for index, (action, status, seconds) in enumerate([
            ("propose_assumption", "approved", "12.5"),
            ("propose_assumption", "rejected", "5.0"),
            ("propose_risk", "suggested", ""),
            ("propose_vulnerability", "approved", "20.0"),
            ("propose_vulnerability", "rejected", "15.0"),
            ("mark_resolved", "rejected", "8.0"),
        ], start=1)
    ]
    for name, rows in [
        ("v_part_summary.csv", parts), ("v_unit_test_results.csv", tests),
        ("v_survey_paired.csv", survey), ("v_survey.csv", all_survey),
        ("v_vulnerability_outcomes.csv", findings),
        ("v_security_state_inventory.csv", inventory), ("v_security_state_decisions.csv", decisions),
    ]:
        write_rows(tmp_path, name, rows)

    output = tmp_path / "analysis"
    output.mkdir()
    for old_name in ("README.md", "vulnerabilities_and_mitigations.md", "security_state.md"):
        (output / old_name).write_text("old report", encoding="utf-8")
    result = analyze_results.analyse(tmp_path, output)

    assert result["eligible_paired_participants"] == 1
    assert result["excluded_by_reason"] == {"pilot": 1, "incomplete": 1}
    assert result["task_pass_rate"]["mean_paired_difference"] == pytest.approx(1 / 3)
    assert result["passed_all_task_tests"] == {"team": 1, "single": 0}
    assert result["survey_by_item"]["security_confidence"]["mean_paired_difference"] == 2
    assert result["team_state"]["accepted"] == 1
    assert result["state_inventory_totals"]["accepted_with_mitigation"] == 1
    assert result["state_inventory_totals"]["mitigations_planned"] == 1
    assert result["state_decisions_by_action"]["propose_assumption"]["statuses"] == {"approved": 1, "rejected": 1}
    assert result["state_decisions_by_action"]["propose_assumption"]["median_decision_seconds"] == 8.75
    assert result["state_decisions_by_action"]["propose_risk"]["statuses"] == {"suggested": 1}
    assert result["fix_choice_counts"] == {"reviewer": 0, "developer": 1, "not_recorded": 0}
    assert result["team_only_survey"]["state_status_tracking"]["answers"] == {"Agree": 1}
    assert result["all_task_tests_passed_paired_test"] is None
    assert result["task_assignment_counts"] == {"team": {"B": 1}, "single": {"A": 1}}
    assert result["task_order_counts"] == {"A -> B": 1}
    assert result["task_mode_sequence_counts"] == {"A/single -> B/team": 1}
    assert result["functional_by_task"]["B"]["team"]["passed_all"] == 1
    with (tmp_path / "analysis" / "paired_parts.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["first_mode"] == "single"
    assert (rows[0]["team_task_id"], rows[0]["single_task_id"]) == ("B", "A")
    report = (output / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# Analysis results\n")
    assert "Starting mode: team **0**, single **1**." in report
    assert "| All tests passed (team) | All tests passed (single) |" in report
    assert "## Activity (v_part_summary.csv; paired_activity.csv)" in report
    assert "## Paired questionnaire answers (v_survey_paired.csv; paired_survey.csv)" in report
    vulnerability_report = report.split("## Vulnerabilities and mitigations (Team Mode)\n", 1)[1].split("## Shared security state (Team Mode)\n", 1)[0]
    assert "| Code Reviewer proposals | 2 |" in vulnerability_report
    assert "| Accepted findings with a mitigation | 1 / 1 |" in vulnerability_report
    assert "| Accepted findings marked fixed | 0 / 1 |" in vulnerability_report
    assert "| Accepted findings with a planned mitigation | 1 / 1 |" in vulnerability_report
    assert "| Accepted findings without a mitigation record | 0 / 1 |" in vulnerability_report
    assert "| Mitigation records added by developer | 1 |" in vulnerability_report
    assert "| Mitigation records marked implemented |" not in vulnerability_report
    assert "| Mitigation records still planned |" not in vulnerability_report
    assert "| Mitigation records |" not in vulnerability_report
    assert "### Per-participant outcomes" not in vulnerability_report
    assert "| Pending |" not in vulnerability_report
    assert "| undecided |" not in vulnerability_report
    assert "### State inventory (v_vulnerability_outcomes.csv; v_security_state_inventory.csv; security_state_parts.csv)" in report
    assert "### Decisions by action (v_security_state_decisions.csv; security_state_decisions.csv)" in report
    assert "| propose_risk | 0 | 0 | 0 | 1 |" in report
    assert report.count("### ") == 4
    assert "### Fix ownership choices" not in report
    assert "### Per-participant state" not in report
    assert "### Team-only questionnaire" not in report
    assert "vulnerabilities_and_mitigations.md" not in report
    assert "security_state.md" not in report
    assert "](" not in report
    for old_name in ("README.md", "vulnerabilities_and_mitigations.md", "security_state.md"):
        assert not (output / old_name).exists()
    with (tmp_path / "analysis" / "security_state_parts.csv").open(newline="", encoding="utf-8") as stream:
        state_rows = list(csv.DictReader(stream))
    assert state_rows[0]["accepted_without_mitigation"] == "0"


def test_sample_participants_are_excluded_from_study_analysis():
    rows = [
        {"participant_code": "SYN001", "participant_status": "complete", "pilot": "False",
         "mode": mode, "task_id": task, "part": str(part), "submitted": "True"}
        for mode, task, part in [("team", "A", 1), ("single", "B", 2)]
    ]
    pairs, exclusions = analyze_results.eligible_pairs(rows)
    assert pairs == {}
    assert exclusions == {"sample_data": 1}


def test_wilcoxon_uses_paired_scores_when_enough_answers_exist():
    calls = []

    def wilcoxon(team, single, **kwargs):
        calls.append((team, single, kwargs))
        return SimpleNamespace(pvalue=0.03125)

    rows = [{"team": 4, "single": 2} for _ in range(5)]
    summary = analyze_results.paired_summary(rows, "team", "single", SimpleNamespace(wilcoxon=wilcoxon))
    assert summary["wilcoxon_p_two_sided_exploratory"] == 0.03125
    assert calls == [([4.0] * 5, [2.0] * 5, {"alternative": "two-sided", "zero_method": "wilcox"})]


def test_pilot_selection_keeps_submitted_pair_even_if_session_was_not_finished():
    rows = [
        {"participant_code": code, "participant_status": status, "pilot": str(pilot),
         "task_id": "B" if code == "P01" and mode == "single" else "A",
         "part": str(part), "mode": mode, "submitted": str(submitted)}
        for code, status, pilot, part, mode, submitted in [
            ("X01", "incomplete", True, 1, "team", True),
            ("X01", "incomplete", True, 2, "single", True),
            ("X02", "active", True, 1, "team", False),
            ("P01", "complete", False, 1, "team", True),
            ("P01", "complete", False, 2, "single", True),
        ]
    ]

    pilots, excluded = analyze_results.eligible_pairs(rows, pilots=True)

    assert list(pilots) == ["X01"]
    assert excluded == {"missing_or_duplicate_mode": 1, "outside_cohort": 1}
    study, excluded = analyze_results.eligible_pairs(rows)
    assert list(study) == ["P01"]
    assert excluded == {"pilot": 2}


def test_new_study_excludes_legacy_same_task_pairs():
    rows = [
        {"participant_code": code, "participant_status": "complete", "pilot": "False",
         "task_id": task_id, "part": str(part), "mode": mode, "submitted": "True"}
        for code, task_id, part, mode in [
            ("P01", "A", 1, "team"), ("P01", "A", 2, "single"),
            ("P02", "A", 1, "single"), ("P02", "B", 2, "team"),
        ]
    ]
    pairs, excluded = analyze_results.eligible_pairs(rows)
    assert list(pairs) == ["P02"]
    assert excluded == {"same_task_legacy_session": 1}
