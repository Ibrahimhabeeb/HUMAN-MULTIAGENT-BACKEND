"""Include recorded security assessments and combined scores in the existing test view.

Revision ID: f15b7c2a6d90
Revises: e4c9a31d70f2
"""

from importlib import import_module

from alembic import op

revision = "f15b7c2a6d90"
down_revision = "e4c9a31d70f2"
branch_labels = None
depends_on = None

ORIGINAL_VIEWS = import_module("migrations.versions.b2866a7f3ded_analysis_views").VIEWS

TEST_RESULTS = f"""
WITH unit_results AS (
    {ORIGINAL_VIEWS['v_unit_test_results']}
), recorded_results AS (
    SELECT u.*,
        COALESCE(s.recorded_runs, 0) AS security_test_runs,
        s.id AS security_assessment_id,
        s.detail ->> 'status' AS security_status,
        s.detail ->> 'suite_version' AS security_suite_version,
        s.detail ->> 'suite_sha256' AS security_suite_sha256,
        s.detail ->> 'snapshot' AS security_snapshot,
        s.detail ->> 'task_id' AS security_task_id,
        (s.detail ->> 'expected')::integer AS security_tests_total,
        (s.detail -> 'counts' ->> 'passed')::integer AS security_tests_passed,
        (s.detail -> 'counts' ->> 'failed')::integer AS security_tests_failed,
        (s.detail -> 'counts' ->> 'error')::integer AS security_tests_error,
        (s.detail -> 'counts' ->> 'skipped')::integer AS security_tests_skipped,
        (s.detail ->> 'not_run')::integer AS security_tests_not_run
    FROM unit_results u
    JOIN workspaces w ON w.participant_code = u.participant_code AND w.mode = u.mode
    LEFT JOIN LATERAL (
        SELECT e.id, e.detail, count(*) OVER () AS recorded_runs
        FROM events e
        WHERE e.participant_code = w.participant_code AND e.mode = w.mode
            AND e.type = 'security_tests_run'
            AND e.detail ->> 'workspace_id' = w.id::text
        ORDER BY e.id DESC
        LIMIT 1
    ) s ON true
), assessed_results AS (
    SELECT r.*, COALESCE(
        submitted AND security_task_id = task_id
        AND security_status IN ('passed', 'failed') AND security_tests_total > 0
        AND security_tests_passed >= 0 AND security_tests_failed >= 0
        AND security_tests_error = 0 AND security_tests_skipped = 0 AND security_tests_not_run = 0
        AND security_tests_passed + security_tests_failed = security_tests_total,
        false
    ) AS security_assessment_complete
    FROM recorded_results r
), combined_results AS (
    SELECT a.*, security_assessment_complete AND task_tests > 0 AND task_tests_not_run = 0
        AND task_tests_passed + task_tests_failed = task_tests AS combined_assessment_complete
    FROM assessed_results a
)
SELECT c.*,
    CASE WHEN security_assessment_complete
        THEN round(security_tests_passed::numeric / security_tests_total, 6) END AS security_pass_rate,
    CASE WHEN security_assessment_complete
        THEN security_tests_passed = security_tests_total END AS all_security_tests_passed,
    CASE WHEN combined_assessment_complete
        THEN task_tests + security_tests_total END AS combined_tests_total,
    CASE WHEN combined_assessment_complete
        THEN task_tests_passed + security_tests_passed END AS combined_tests_passed,
    CASE WHEN combined_assessment_complete
        THEN task_tests_failed + security_tests_failed END AS combined_tests_failed,
    CASE WHEN combined_assessment_complete
        THEN round((task_tests_passed + security_tests_passed)::numeric
                   / (task_tests + security_tests_total), 6) END AS combined_pass_rate,
    CASE WHEN combined_assessment_complete
        THEN task_tests_passed + security_tests_passed = task_tests + security_tests_total
        END AS all_combined_tests_passed
FROM combined_results c
"""


def upgrade() -> None:
    op.execute(f"CREATE OR REPLACE VIEW v_unit_test_results AS {TEST_RESULTS}")


def downgrade() -> None:
    # The dependent summary uses the original unit columns. Recreate it when removing appended columns.
    op.execute("DROP VIEW v_part_summary")
    op.execute("DROP VIEW v_unit_test_results")
    op.execute(f"CREATE VIEW v_unit_test_results AS {ORIGINAL_VIEWS['v_unit_test_results']}")
    op.execute(f"CREATE VIEW v_part_summary AS {ORIGINAL_VIEWS['v_part_summary']}")
