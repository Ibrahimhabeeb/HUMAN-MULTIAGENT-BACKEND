"""Researcher only: writes results/survey.csv, one row per participant, for analysis. With PostgreSQL it also writes
each analysis view (migrations/versions/*_analysis_views.py) to results/<view>.csv.

Pilot participants (X codes) and withdrawn participants are left out.

    uv run python export.py
"""

import csv
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db import SessionLocal, init_db
from models import Participant, SurveyResponse, Workspace
from services import questionnaire

OUTPUT = Path("results/survey.csv")
VIEWS = ["v_part_summary", "v_vulnerability_outcomes", "v_unit_test_results", "v_survey", "v_survey_paired"]


def column(condition: str, item: str) -> str:
    return item if condition == "none" else f"{item}_{condition}"


def export(db: Session, path: Path = OUTPUT) -> int:
    questions = questionnaire.asked(questionnaire.load())
    columns = ["participant", "first_mode", *(column(c, item) for c, item in questions)]
    participants = select(Participant).where(~Participant.code.startswith("X"), Participant.status != "withdrawn")

    rows = []
    for participant in db.scalars(participants.order_by(Participant.n)):
        responses = db.scalars(select(SurveyResponse).where(SurveyResponse.participant_code == participant.code))
        answers = {(r.condition, r.item): r.value for r in responses}
        if not answers:
            continue  # they never submitted the questionnaire
        first_mode = db.scalar(
            select(Workspace.mode).where(Workspace.participant_code == participant.code, Workspace.part == 1)
        )
        row = {"participant": participant.code, "first_mode": first_mode}
        rows.append(row | {column(c, item): answers.get((c, item)) for c, item in questions})

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def export_views(db: Session, folder: Path = OUTPUT.parent) -> dict[str, int]:
    # PostgreSQL only: the views are created by the migrations. Returns the rows written per view.
    written = {}
    folder.mkdir(parents=True, exist_ok=True)
    for view in VIEWS:
        query = text(f"SELECT * FROM {view} WHERE NOT pilot AND participant_status <> 'withdrawn'")  # fixed names only
        result = db.execute(query)
        rows = result.all()
        with (folder / f"{view}.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(result.keys())
            writer.writerows(rows)
        written[view] = len(rows)
    return written


if __name__ == "__main__":
    init_db()
    with SessionLocal() as session:
        count = export(session)
        print(f"Wrote {count} participant(s) to {OUTPUT}")
        if session.get_bind().dialect.name == "postgresql":
            for view, rows in export_views(session).items():
                print(f"Wrote {rows} row(s) to {OUTPUT.parent / view}.csv")
