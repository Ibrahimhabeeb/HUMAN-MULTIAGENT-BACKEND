import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event as ThreadEvent
from time import monotonic, sleep

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import main
from config import get_settings
from db import get_db, init_db
from main import app
from models import Event, Participant
from services import runner, security_assessment, study, submissions
from services.assessment_worker import FINISHED, AssessmentWorker


def test_finish_and_questionnaire_never_wait_for_an_assessment(client, db, enrol, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Finish must only save the submission, not run an assessment")

    monkeypatch.setattr(submissions, "assess", unexpected)
    enrol(task_id="C")
    first = client.post("/study/done")
    assert first.status_code == 200 and first.json()["screen"] == "part_complete"
    assert client.put("/workspace/files/app/comments.py", json={"content": "# late edit"}).status_code == 409
    assert client.post("/study/part-two", json={"task_id": "B"}).json()["mode"] == "single"
    assert client.post("/study/done").json()["screen"] == "questionnaire"
    assert db.query(Event).filter_by(type="submission_assessment_pending").count() == 2
    assert db.query(Event).filter(Event.type.in_(("tests_run", "security_tests_run"))).count() == 0


def test_queued_assessment_survives_a_new_worker_without_repeating_results(client, db, team):
    client.post("/study/done")
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    assert AssessmentWorker(factory).process_one()
    assert not AssessmentWorker(factory).process_one()
    assert db.query(Event).filter_by(type="tests_run").count() == 1
    assert db.query(Event).filter_by(type="security_tests_run").count() == 1
    assert db.query(Event).filter_by(type=FINISHED).one().detail["status"] == "complete"


def test_restart_reuses_the_unit_result_recorded_before_an_interruption(client, db, team, monkeypatch):
    ws = study.current_workspace(db)
    snapshot = study._mark_done(db, ws)
    runner.run_tests(db, ws, trigger="finish", saved_snapshot=snapshot)

    def duplicate(*args, **kwargs):
        pytest.fail("The unit suite already has a final result for this snapshot")

    monkeypatch.setattr(runner, "run_tests", duplicate)
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    assert AssessmentWorker(factory).process_one()
    assert db.query(Event).filter_by(type="tests_run").count() == 1
    assert db.query(Event).filter_by(type="security_tests_run").count() == 1


@pytest.mark.parametrize("problem", ["runner-error", "exception", "missing-snapshot"])
def test_errors_are_retained_without_a_tight_retry_loop(client, db, team, monkeypatch, problem):
    client.post("/study/done")
    if problem == "runner-error":
        monkeypatch.setattr(runner, "_pytest", lambda folder: (3, [], "Runner unavailable"))
    else:
        def recover(*args, **kwargs):
            if problem == "exception":
                raise RuntimeError("Private diagnostic must not be copied into event output")
            return False
        monkeypatch.setattr(submissions, "recover", recover)
    worker = AssessmentWorker(sessionmaker(bind=db.get_bind(), expire_on_commit=False))
    assert worker.process_one()
    assert not worker.process_one()
    event = db.query(Event).filter_by(type=FINISHED).one()
    assert event.detail["status"] == "needs_attention"
    assert "Private diagnostic" not in str(event.detail)
    assert db.query(Event).filter_by(type="submission_assessed").count() == 0


def test_one_failed_job_does_not_block_the_other_mode(client, db, enrol, monkeypatch):
    enrol(task_id="C")
    client.post("/study/done")
    client.post("/study/part-two", json={"task_id": "B"})
    client.post("/study/done")
    seen = []

    def recover(db, ws):
        seen.append((ws.mode, ws.task_id))
        if ws.mode == "team":
            raise RuntimeError("Broken first job")
        return True

    monkeypatch.setattr(submissions, "recover", recover)
    worker = AssessmentWorker(sessionmaker(bind=db.get_bind(), expire_on_commit=False))
    assert worker.process_one() and worker.process_one()
    assert not worker.process_one()
    assert seen == [("team", "C"), ("single", "B")]
    assert [event.detail["status"] for event in db.query(Event).filter_by(type=FINISHED).order_by(Event.id)] == [
        "needs_attention", "complete",
    ]


def test_withdrawn_participants_are_not_assessed(client, db, team, monkeypatch):
    client.post("/study/done")
    db.scalar(select(Participant).where(Participant.code == team["participant"])).status = "withdrawn"
    db.commit()
    monkeypatch.setattr(submissions, "recover", lambda *args, **kwargs: pytest.fail("Withdrawn participant assessed"))
    assert not AssessmentWorker(sessionmaker(bind=db.get_bind())).process_one()


@pytest.fixture
def worker_store(client, tmp_path):
    # Real separate connections are required to check requests during a blocked job.
    engine = create_engine(f"sqlite:///{(tmp_path / 'worker.db').as_posix()}", connect_args={"check_same_thread": False})
    init_db(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    previous = app.dependency_overrides[get_db]

    def isolated_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = isolated_db
    yield factory
    app.dependency_overrides[get_db] = previous
    engine.dispose()


def test_task_two_and_questionnaire_open_while_background_tests_are_blocked(
    client, enrol, worker_store, monkeypatch, sample_questionnaire,
):
    started, release = ThreadEvent(), ThreadEvent()
    seen = []

    def evaluate(snapshot, task_id):
        seen.append((snapshot, task_id))
        if task_id == "C":
            started.set()
            assert release.wait(10)
        expected = {"C": 12, "B": 8}[task_id]
        return {"status": "passed", "all_passed": True, "counts": {"passed": expected, "failed": 0, "error": 0, "skipped": 0},
                "tests": [], "expected": expected, "not_run": 0, "suite_version": "test", "suite_sha256": "a" * 64}

    monkeypatch.setattr(security_assessment, "evaluate_snapshot", evaluate)
    enrol(task_id="C")
    worker = AssessmentWorker(worker_store, poll_seconds=0.01)
    worker.start()
    try:
        assert client.post("/study/done").json()["screen"] == "part_complete"
        assert started.wait(10)
        assert not worker.process_one()  # The same consumer cannot take a second job concurrently.
        with ThreadPoolExecutor(max_workers=1) as requests:
            next_part = requests.submit(client.post, "/study/part-two", json={"task_id": "B"}).result(timeout=3)
            assert next_part.json()["mode"] == "single"
            finished = requests.submit(client.post, "/study/done").result(timeout=3)
            assert finished.json()["screen"] == "questionnaire"
            survey = requests.submit(client.post, "/study/questionnaire", json={"answers": []}).result(timeout=3)
            assert survey.json()["screen"] == "thank_you"
            assert requests.submit(client.post, "/study/finish").result(timeout=3).json()["screen"] == "start"
        release.set()
        deadline = monotonic() + 10
        while monotonic() < deadline:
            with worker_store() as db:
                results = db.scalars(select(Event).where(Event.type == FINISHED).order_by(Event.id)).all()
            if len(results) == 2:
                break
            sleep(0.02)
        assert [(event.mode, event.detail["status"]) for event in results] == [("team", "complete"), ("single", "complete")]
        assert [task for _, task in seen] == ["C", "B"]
        assert [path.parent.name for path, _ in seen] == ["P01_C_team", "P01_B_single"]
        assert all(path.is_relative_to(get_settings().snapshots_dir) for path, _ in seen)
    finally:
        release.set()
        worker.stop()
    assert not worker.thread.is_alive()


def test_api_startup_recovers_backlog_and_shutdown_stops_worker(client, enrol, worker_store, monkeypatch):
    enrol(task_id="C")
    assert client.post("/study/done").status_code == 200
    instances = []

    def consumer(factory):
        worker = AssessmentWorker(factory, poll_seconds=0.01)
        instances.append(worker)
        return worker

    monkeypatch.setattr(main, "SessionLocal", worker_store)
    monkeypatch.setattr(main, "init_db", lambda: None)  # The isolated database is already initialised.
    monkeypatch.setattr(main, "AssessmentWorker", consumer)

    async def restart():
        async with main.lifespan(app):
            deadline = monotonic() + 10
            while monotonic() < deadline:
                with worker_store() as db:
                    if db.scalar(select(Event.id).where(Event.type == FINISHED)):
                        return
                await asyncio.sleep(0.02)
            pytest.fail("Startup did not recover the queued submission")

    asyncio.run(restart())
    assert len(instances) == 1 and not instances[0].thread.is_alive()
