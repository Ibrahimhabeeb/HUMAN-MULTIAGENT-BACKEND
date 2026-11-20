"""Private recovery command for final assessments interrupted during Finish part."""

import argparse

from sqlalchemy import select

from db import SessionLocal, init_db
from models import Participant, Workspace
from services import submissions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retry-errors", action="store_true", help="also rerun error and timeout results on the same saved code")
    args = parser.parse_args()
    init_db()
    counts = {"assessed": 0, "needs_attention": 0}
    with SessionLocal() as db:
        parts = db.scalars(select(Workspace).join(Participant, Participant.code == Workspace.participant_code).where(
            Workspace.done_at.is_not(None), Participant.status != "withdrawn", ~Participant.code.startswith("SYN"),
        )).all()
        for ws in parts:
            finished = submissions.recover(db, ws, retry_errors=args.retry_errors)
            counts["assessed" if finished else "needs_attention"] += 1
    print(counts)


if __name__ == "__main__":
    main()
