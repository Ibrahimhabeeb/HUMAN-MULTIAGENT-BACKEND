"""Researcher only: deletes everything stored for one participant, when they ask to withdraw.

Their rows go from every table except participants, their workspace and snapshot folders are deleted,
and they are marked withdrawn, so their ID is never given to anyone else.

    uv run python withdraw.py P07
"""

import argparse
import shutil
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from config import get_settings
from db import Base, SessionLocal, init_db
from models import Participant, Workspace


class WithdrawError(Exception):
    pass


def withdraw(db: Session, code: str) -> list[Path]:
    participant = db.scalar(select(Participant).where(Participant.code == code))
    if participant is None:
        raise WithdrawError(f"There is no participant {code}")
    if participant.status == "active":
        raise WithdrawError(f"{code} is in the current session; click Restart for new participant first")
    if participant.status == "withdrawn":
        raise WithdrawError(f"{code} has already been withdrawn")

    their_parts = select(Workspace.id).where(Workspace.participant_code == code)
    for table in reversed(Base.metadata.sorted_tables):  # tables that point to others go first
        if "participant_code" in table.c:
            db.execute(delete(table).where(table.c.participant_code == code))
        elif "workspace_id" in table.c:  # their parts' security state and unit tests
            db.execute(delete(table).where(table.c.workspace_id.in_(their_parts)))
    participant.status = "withdrawn"
    db.commit()

    settings = get_settings()
    folders = [folder for base in (settings.workspaces_dir, settings.snapshots_dir) for folder in Path(base).glob(f"{code}_*")]
    for folder in folders:
        shutil.rmtree(folder)
    return folders


def main() -> None:
    parser = argparse.ArgumentParser(description="Delete all data stored for one participant.")
    parser.add_argument("code", help="the participant ID, e.g. P07")
    parser.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    args = parser.parse_args()
    code = args.code.strip().upper()

    if not args.yes:
        typed = input(f"Delete all data of {code}? This can't be undone. Type {code} to confirm: ")
        if typed.strip().upper() != code:
            print("Nothing was deleted.")
            return
    init_db()
    with SessionLocal() as session:
        try:
            folders = withdraw(session, code)
        except WithdrawError as e:
            raise SystemExit(str(e)) from e
    print(f"{code} is withdrawn: their rows and {len(folders)} folder(s) were deleted.")
    print("Run export.py again so results/survey.csv no longer includes them.")


if __name__ == "__main__":
    main()
