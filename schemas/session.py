from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SessionInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    created_at: datetime
    ended_at: datetime | None
