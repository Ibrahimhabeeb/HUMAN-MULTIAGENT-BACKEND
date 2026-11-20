"""Export team security-state inventory and decisions for analysis.

Revision ID: e4c9a31d70f2
Revises: b2866a7f3ded
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e4c9a31d70f2"
down_revision: str | Sequence[str] | None = "b2866a7f3ded"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PART = """
    w.participant_code, p.status AS participant_status, w.participant_code LIKE 'X%' AS pilot,
    w.task_id, w.part, w.mode, w.done_at IS NOT NULL AS submitted"""

INVENTORY = f"""
SELECT {PART},
    (SELECT count(*) FROM assumptions a WHERE a.workspace_id = w.id) AS assumptions_total,
    (SELECT count(*) FROM risks r WHERE r.workspace_id = w.id) AS risks_total,
    (SELECT count(*) FROM mitigations m WHERE m.workspace_id = w.id) AS mitigations_total,
    (SELECT count(*) FROM mitigations m WHERE m.workspace_id = w.id AND m.source = 'human') AS mitigations_human,
    (SELECT count(*) FROM mitigations m WHERE m.workspace_id = w.id AND m.status = 'planned') AS mitigations_planned,
    (SELECT count(*) FROM mitigations m WHERE m.workspace_id = w.id AND m.status = 'implemented') AS mitigations_implemented,
    (SELECT count(*) FROM vulnerabilities v WHERE v.workspace_id = w.id AND v.status = 'accepted'
        AND EXISTS (SELECT 1 FROM mitigations m WHERE m.vulnerability_id = v.id)) AS accepted_with_mitigation,
    (SELECT count(*) FROM vulnerabilities v WHERE v.workspace_id = w.id AND v.status = 'accepted'
        AND EXISTS (SELECT 1 FROM mitigations m WHERE m.vulnerability_id = v.id AND m.status = 'implemented'))
        AS accepted_with_implemented_mitigation
FROM workspaces w
JOIN participants p ON p.code = w.participant_code
WHERE w.mode = 'team'"""

DECISIONS = f"""
SELECT {PART}, a.id AS approval_id, a.actor, a.action_type, a.status AS decision_status,
    a.result ->> 'fix_choice' AS fix_choice,
    round(EXTRACT(EPOCH FROM (a.decided_at - a.requested_at))::numeric, 1) AS decision_seconds
FROM workspaces w
JOIN participants p ON p.code = w.participant_code
JOIN approvals a ON a.workspace_id = w.id
WHERE w.mode = 'team'
    AND a.action_type IN ('propose_assumption', 'propose_risk', 'propose_vulnerability', 'mark_resolved', 'write_fix')"""


def upgrade() -> None:
    op.execute(f"CREATE VIEW v_security_state_inventory AS {INVENTORY}")
    op.execute(f"CREATE VIEW v_security_state_decisions AS {DECISIONS}")


def downgrade() -> None:
    op.execute("DROP VIEW v_security_state_decisions")
    op.execute("DROP VIEW v_security_state_inventory")
