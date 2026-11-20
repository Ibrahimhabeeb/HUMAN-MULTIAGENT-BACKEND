import csv

import pytest

import analyze_results


def write_csv(folder, filename, rows):
    with (folder / filename).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else ["participant_code"])
        writer.writeheader()
        writer.writerows(rows)


def functional_exports(folder):
    parts, tests = [], []
    for part, mode, task_id in [(1, "team", "A"), (2, "single", "B")]:
        parts.append({
            "participant_code": "P01", "participant_status": "complete", "pilot": "False",
            "task_id": task_id, "part": part, "mode": mode, "submitted": "True",
            "reviews": 1, "test_runs": 1, "messages_typed": 2, "seconds_on_task": 100,
        })
        tests.append({
            "participant_code": "P01", "mode": mode, "task_id": task_id, "task_tests": 3,
            "task_tests_passed": 3, "task_tests_not_run": 0, "all_task_tests_passed": "True",
        })
    write_csv(folder, "v_part_summary.csv", parts)
    write_csv(folder, "v_unit_test_results.csv", tests)
    for filename in (
        "v_survey_paired.csv", "v_survey.csv", "v_vulnerability_outcomes.csv",
        "v_security_state_inventory.csv", "v_security_state_decisions.csv",
    ):
        write_csv(folder, filename, [])
    context = {"participant_code": "P01", "mode": "team", "task_id": "A", "part": 1, "submitted": "True"}
    write_csv(folder, "v_vulnerability_outcomes.csv", [context | dict.fromkeys(analyze_results.VULNERABILITY_FIELDS, 0)])
    write_csv(folder, "v_security_state_inventory.csv", [context | dict.fromkeys(analyze_results.INVENTORY_FIELDS, 0)])


def assessments():
    return [
        {"participant_code": "P01", "mode": mode, "task_id": task_id,
         "security_task_id": task_id, "security_suite_version": "1",
         "security_tests_total": expected, "security_tests_passed": passed, "security_tests_failed": expected - passed,
         "security_tests_error": 0, "security_tests_skipped": 0, "security_tests_not_run": 0,
         "security_assessment_complete": True, "security_status": "passed" if passed == expected else "failed"}
        for mode, task_id, expected, passed in [("team", "A", 12, 6), ("single", "B", 8, 8)]
    ]


def write_assessments(folder, assessments):
    with (folder / "v_unit_test_results.csv").open(newline="", encoding="utf-8") as stream:
        tests = list(csv.DictReader(stream))
    for test, assessment in zip(tests, assessments):
        test.update(assessment)
        test.update({
            "combined_assessment_complete": True,
            "combined_tests_total": int(test["task_tests"]) + test["security_tests_total"],
            "combined_tests_passed": int(test["task_tests_passed"]) + test["security_tests_passed"],
            "combined_tests_failed": test["security_tests_failed"],
        })
    write_csv(folder, "v_unit_test_results.csv", tests)


def test_security_scores_appear_in_the_existing_test_section_with_type_labels(tmp_path):
    functional_exports(tmp_path)
    write_assessments(tmp_path, assessments())
    output = tmp_path / "analysis"
    output.mkdir()
    (output / "paired_task_tests.csv").write_text("old combined export")
    result = analyze_results.analyse(tmp_path, tmp_path / "analysis")
    assert result["functional_pairs"] == result["security_test_pairs"] == 1
    assert result["combined_test_pairs"] == 1
    assert result["task_pass_rate"]["team_median"] == 1
    assert result["security_pass_rate"]["team_median"] == 0.5
    assert result["security_pass_rate"]["single_median"] == 1
    assert result["security_passed_all"] == {"team": 0, "single": 1}
    assert result["combined_pass_rate"]["team_median"] == 9 / 15
    assert result["combined_pass_rate"]["single_median"] == 1
    assert result["test_results_by_type"]["combined"]["team"] == {
        "submissions": 1, "passed": 9, "total": 15, "pass_rate": 0.6,
        "median_pass_rate": 0.6, "all_passed": 0,
    }
    assert result["security_pass_rate"]["wilcoxon_p_two_sided_exploratory"] is None
    report = (tmp_path / "analysis" / "report.md").read_text()
    test_section = report.split("## Unit and security tests", 1)[1].split("## Activity", 1)[0]
    assert "| P01 | Unit |" in test_section
    assert "| P01 | Security |" in test_section
    assert "| P01 | Combined |" in test_section
    assert "| Combined | team | 1 | 9 | 15 | 60.0% | 60.0% | 0 |" in test_section
    with (tmp_path / "analysis" / "paired_parts.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["team_pass_rate"] == "1.0"
    assert rows[0]["team_security_pass_rate"] == "0.5"
    assert rows[0]["team_combined_pass_rate"] == "0.6"
    assert rows[0]["team_security_tests_failed"] == "6"
    assert rows[0]["team_combined_tests_total"] == "15"
    assert not (output / "paired_task_tests.csv").exists()


def test_old_exports_keep_missing_security_assessments_unscored(tmp_path):
    functional_exports(tmp_path)
    result = analyze_results.analyse(tmp_path, tmp_path / "analysis")
    assert result["functional_pairs"] == 1
    assert result["security_test_pairs"] == 0
    assert result["security_pass_rate"]["team_median"] is None
    assert result["security_excluded_by_reason"] == {"missing_assessment": 1}
    assert result["combined_test_pairs"] == 0
    with (tmp_path / "analysis" / "paired_parts.csv").open(newline="", encoding="utf-8") as stream:
        row, = csv.DictReader(stream)
    assert row["team_security_pass_rate"] == row["single_combined_pass_rate"] == ""


@pytest.mark.parametrize("changes,reason", [
    ({"security_status": "timed_out", "security_tests_passed": 0, "security_tests_failed": 0, "security_tests_not_run": 12}, "incomplete_or_error"),
    ({"task_id": "C"}, "task_mismatch"),
    ({"security_suite_version": "2"}, "suite_version_mismatch"),
    ({"security_tests_passed": 12, "security_tests_failed": 0, "security_tests_skipped": 1}, "incomplete_or_error"),
    ({"security_assessment_complete": False}, "incomplete_or_error"),
])
def test_invalid_assessment_pairs_are_not_reported_as_security_passes(tmp_path, changes, reason):
    functional_exports(tmp_path)
    rows = assessments()
    rows[0].update(changes)
    write_assessments(tmp_path, rows)
    result = analyze_results.analyse(tmp_path, tmp_path / "analysis")
    assert result["security_test_pairs"] == 0
    assert result["security_excluded_by_reason"] == {reason: 1}


def test_combined_scores_use_consistent_database_counts(tmp_path):
    functional_exports(tmp_path)
    write_assessments(tmp_path, assessments())
    with (tmp_path / "v_unit_test_results.csv").open(newline="", encoding="utf-8") as stream:
        tests = list(csv.DictReader(stream))
    tests[0]["combined_tests_total"] = "14"
    write_csv(tmp_path, "v_unit_test_results.csv", tests)
    result = analyze_results.analyse(tmp_path, tmp_path / "analysis")
    assert result["functional_pairs"] == result["security_test_pairs"] == 1
    assert result["combined_test_pairs"] == 0
    assert result["combined_excluded_by_reason"] == {"inconsistent_combined_counts": 1}
