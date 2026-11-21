"""One background consumer of the final assessments already recorded in PostgreSQL."""

import logging
from threading import Event as StopEvent
from threading import Lock, Thread

from sqlalchemy import exists, select
from sqlalchemy.orm import aliased

from models import Event, Participant, Workspace
from services import submissions
from services.events import log_event

log = logging.getLogger(__name__)
FINISHED = "submission_assessment_finished"


class AssessmentWorker:
    def __init__(self, session_factory, *, poll_seconds=2):
        self.session_factory = session_factory
        self.poll_seconds = poll_seconds
        self.stopping = StopEvent()
        self.processing = Lock()
        self.thread = Thread(target=self._run, name="submission-assessments", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=5)

    def _run(self):
        while not self.stopping.is_set():
            try:
                if self.process_one():
                    continue
            except Exception as error:  # noqa: BLE001 -- leave database outages pending for the next poll
                log.error("Assessment worker could not poll (%s)", type(error).__name__)
            self.stopping.wait(self.poll_seconds)

    def process_one(self):
        # One consumer also bounds memory and runner load on the 2 GB server.
        if not self.processing.acquire(blocking=False):
            return False
        try:
            return self._process_one()
        finally:
            self.processing.release()

    def _process_one(self):
        pending = aliased(Event)
        finished = exists(select(Event.id).where(
            Event.participant_code == pending.participant_code, Event.mode == pending.mode,
            Event.type.in_(("submission_assessed", FINISHED)),
            Event.detail["snapshot"].as_string() == pending.detail["snapshot"].as_string(),
        ))
        with self.session_factory() as db:
            job = db.scalar(select(pending).join(Participant, Participant.code == pending.participant_code).join(
                Workspace, (Workspace.id == pending.detail["workspace_id"].as_integer())
                & (Workspace.participant_code == pending.participant_code) & (Workspace.mode == pending.mode),
            ).where(
                pending.type == "submission_assessment_pending", Workspace.done_at.is_not(None),
                Participant.status != "withdrawn", ~Participant.code.startswith("SYN"), ~finished,
            ).order_by(pending.id).limit(1))
            if job is None:
                return False
            # Copy identifiers before assessment commits/rollbacks. Never use the
            # participant's current mode or a request's database session here.
            code, mode = job.participant_code, job.mode
            detail = dict(job.detail)
            ws = db.get(Workspace, detail["workspace_id"])
            try:
                complete = submissions.recover(db, ws)
                status = "complete" if complete else "needs_attention"
            except Exception as error:  # noqa: BLE001 -- retain a failed job without stopping later assessments
                db.rollback()
                status = "needs_attention"
                detail["error_type"] = type(error).__name__
                log.error("Final assessment failed for workspace %s (%s)", detail["workspace_id"], type(error).__name__)
            log_event(db, code, FINISHED, actor="system", mode=mode, detail=detail | {"status": status})
            db.commit()
            return True
