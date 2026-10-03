from sqlalchemy import select
from sqlalchemy.orm import Session

from models import ChatSession, Project
from models.common import utc_now
from schemas.project import ProjectCreate
from schemas.security_state import SecurityState
from services.errors import ConflictError, NotFoundError
from services.paths import normalise_files

# ---- projects ------------------------------------------------------------------------


def create_project(db: Session, data: ProjectCreate) -> Project:
    project = Project(
        name=data.name,
        user_id=data.user_id,
        files=normalise_files(data.files),
        security_state=SecurityState().model_dump(mode="json"),
    )
    db.add(project)
    db.commit()
    return project


def get_project(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError(f"Project {project_id} not found")
    return project


def list_projects(db: Session, user_id: str | None = None) -> list[Project]:
    query = select(Project).order_by(Project.created_at)
    if user_id is not None:
        query = query.where(Project.user_id == user_id)
    return list(db.scalars(query))


# ---- sessions --------------------------------------------------------------------------


def start_session(db: Session, project_id: str) -> ChatSession:
    get_project(db, project_id)
    session = ChatSession(project_id=project_id)
    db.add(session)
    db.commit()
    return session


def get_session(db: Session, session_id: str) -> ChatSession:
    session = db.get(ChatSession, session_id)
    if session is None:
        raise NotFoundError(f"Session {session_id} not found")
    return session


def list_sessions(db: Session, project_id: str) -> list[ChatSession]:
    get_project(db, project_id)
    query = select(ChatSession).where(ChatSession.project_id == project_id).order_by(ChatSession.created_at)
    return list(db.scalars(query))


def open_session(db: Session, project_id: str, session_id: str) -> ChatSession:
    # Changes to a project must come from a live session of that project.
    session = get_session(db, session_id)
    if session.project_id != project_id:
        raise NotFoundError(f"Session {session_id} not found in project {project_id}")
    if session.ended_at is not None:
        raise ConflictError(f"Session {session_id} has ended")
    return session


def end_session(db: Session, session_id: str) -> ChatSession:
    session = get_session(db, session_id)
    if session.ended_at is not None:
        raise ConflictError(f"Session {session_id} has already ended")
    session.ended_at = utc_now()
    db.commit()
    return session
