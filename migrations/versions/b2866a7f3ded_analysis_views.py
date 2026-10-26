"""Analysis views: the study's statistics as saved queries, one row per part or answer.

Open them in pgAdmin (Schemas > public > Views) or export them with export.py. Each row says whether the participant
is a pilot (X codes) and their status, so pilots and withdrawn participants are easy to leave out.

Revision ID: b2866a7f3ded
Revises: 0188d85346ca
Create Date: 2026-10-26 17:04:09.799352
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b2866a7f3ded"
down_revision: str | Sequence[str] | None = "0188d85346ca"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Who and which part each row is about.
PART = """
    w.participant_code, p.status AS participant_status, w.participant_code LIKE 'X%' AS pilot,
    w.task_id, w.part, w.mode, w.done_at IS NOT NULL AS submitted"""

VIEWS = {
    # Team parts: the Code Reviewer's findings, the developer's decisions on them, and whether they were fixed.
    "v_vulnerability_outcomes": f"""
SELECT {PART},
    (SELECT count(*) FROM approvals a
     WHERE a.workspace_id = w.id AND a.action_type = 'propose_vulnerability') AS proposed_by_reviewer,
    (SELECT count(*) FROM approvals a
     WHERE a.workspace_id = w.id AND a.action_type = 'propose_vulnerability' AND a.status = 'pending') AS undecided,
    count(v.id) FILTER (WHERE v.status = 'accepted') AS accepted,
    count(v.id) FILTER (WHERE v.status = 'rejected') AS rejected,
    count(v.id) FILTER (WHERE v.source = 'human') AS added_by_participant,
    count(v.id) FILTER (WHERE v.status = 'accepted' AND fix.implemented) AS fixed,
    count(v.id) FILTER (WHERE v.status = 'accepted' AND fix.planned AND NOT fix.implemented) AS fix_planned,
    count(v.id) FILTER (WHERE v.status = 'accepted' AND fix.vulnerability_id IS NULL) AS no_fix
FROM workspaces w
JOIN participants p ON p.code = w.participant_code
LEFT JOIN vulnerabilities v ON v.workspace_id = w.id
LEFT JOIN (
    SELECT vulnerability_id, bool_or(status = 'implemented') AS implemented, bool_or(status = 'planned') AS planned
    FROM mitigations GROUP BY vulnerability_id
) fix ON fix.vulnerability_id = v.id
WHERE w.mode = 'team'
GROUP BY w.id, p.status""",
    # Both modes: each unit test's latest result. Finishing a part runs them last, so once submitted these are the
    # final results. "task" tests come with the task (the fair comparison); "own" tests are ones the developer wrote.
    "v_unit_test_results": f"""
SELECT {PART},
    count(t.id) FILTER (WHERE t.source = 'system') AS task_tests,
    count(t.id) FILTER (WHERE t.source = 'system' AND t.status = 'passed') AS task_tests_passed,
    count(t.id) FILTER (WHERE t.source = 'system' AND t.status = 'failed') AS task_tests_failed,
    count(t.id) FILTER (WHERE t.source = 'system' AND t.status = 'open') AS task_tests_not_run,
    round(count(t.id) FILTER (WHERE t.source = 'system' AND t.status = 'passed')::numeric
          / NULLIF(count(t.id) FILTER (WHERE t.source = 'system'), 0), 2) AS task_pass_rate,
    count(t.id) FILTER (WHERE t.source = 'system') > 0
        AND count(t.id) FILTER (WHERE t.source = 'system' AND t.status <> 'passed') = 0 AS all_task_tests_passed,
    count(t.id) FILTER (WHERE t.source = 'human') AS own_tests,
    count(t.id) FILTER (WHERE t.source = 'human' AND t.status = 'passed') AS own_tests_passed
FROM workspaces w
JOIN participants p ON p.code = w.participant_code
LEFT JOIN unit_tests t ON t.workspace_id = w.id
GROUP BY w.id, p.status""",
    # Every questionnaire answer with its question. score = value_num, reversed for negatively worded questions.
    "v_survey": """
SELECT r.participant_code, p.status AS participant_status, r.participant_code LIKE 'X%' AS pilot,
    r.condition, i.number, r.item, i.section, i.type, r.value, r.value_num,
    CASE WHEN i.reverse_scored AND r.value_num IS NOT NULL THEN i.scale_min + i.scale_max - r.value_num
         ELSE r.value_num END AS score
FROM survey_responses r
JOIN participants p ON p.code = r.participant_code
JOIN questionnaire_items i ON i.key = r.item""",
    # The per-mode questions, team and single side by side for each participant: ready for paired tests.
    "v_survey_paired": """
SELECT t.participant_code, t.participant_status, t.pilot, t.number, t.item,
    t.value AS team_answer, s.value AS single_answer,
    t.score AS team_score, s.score AS single_score, t.score - s.score AS team_minus_single
FROM v_survey t
JOIN v_survey s ON s.participant_code = t.participant_code AND s.item = t.item AND s.condition = 'single'
WHERE t.condition = 'team'""",
    # One row per part: time, activity and decisions, with the test and vulnerability results above.
    "v_part_summary": f"""
SELECT {PART},
    round(EXTRACT(EPOCH FROM (w.done_at - w.started_at)))::int AS seconds_on_task,
    (SELECT count(*) FROM events e
     WHERE e.participant_code = w.participant_code AND e.mode = w.mode AND e.type = 'ready_for_review') AS reviews,
    (SELECT count(*) FROM events e
     WHERE e.participant_code = w.participant_code AND e.mode = w.mode AND e.type = 'tests_run') AS test_runs,
    (SELECT count(*) FROM events e
     WHERE e.participant_code = w.participant_code AND e.mode = w.mode AND e.type = 'message_sent') AS messages_typed,
    (SELECT count(*) FROM approvals a WHERE a.workspace_id = w.id AND a.status = 'approved') AS proposals_approved,
    (SELECT count(*) FROM approvals a WHERE a.workspace_id = w.id AND a.status = 'rejected') AS proposals_rejected,
    (SELECT count(*) FROM approvals a WHERE a.workspace_id = w.id AND a.status = 'pending') AS proposals_undecided,
    (SELECT round(avg(EXTRACT(EPOCH FROM (a.decided_at - a.requested_at))), 1) FROM approvals a
     WHERE a.workspace_id = w.id AND a.decided_at IS NOT NULL) AS avg_decision_seconds,
    (SELECT count(*) FROM risks r WHERE r.workspace_id = w.id) AS risks,
    t.task_tests, t.task_tests_passed, t.task_tests_failed, t.task_pass_rate, t.all_task_tests_passed,
    v.accepted AS vulnerabilities_accepted, v.rejected AS vulnerabilities_rejected, v.fixed AS vulnerabilities_fixed
FROM workspaces w
JOIN participants p ON p.code = w.participant_code
LEFT JOIN v_unit_test_results t ON t.participant_code = w.participant_code AND t.mode = w.mode
LEFT JOIN v_vulnerability_outcomes v ON v.participant_code = w.participant_code AND v.mode = w.mode""",
}


def upgrade() -> None:
    for name, query in VIEWS.items():  # in order: later views use earlier ones
        op.execute(f"CREATE VIEW {name} AS {query}")


def downgrade() -> None:
    for name in reversed(list(VIEWS)):
        op.execute(f"DROP VIEW IF EXISTS {name}")
