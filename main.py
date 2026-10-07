from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.approvals import router as approvals_router
from api.chat import router as chat_router
from api.study import router as study_router
from api.workspace import router as workspace_router
from db import init_db
from services import questionnaire


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    init_db()
    questionnaire.check()
    yield


app = FastAPI(title="Secure Coding Room API", version="0.1.0", lifespan=lifespan)

FRONTEND_ORIGINS = [
    "http://localhost:5001",
    "http://127.0.0.1:5001",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(study_router)
app.include_router(workspace_router)
app.include_router(approvals_router)
app.include_router(chat_router)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
