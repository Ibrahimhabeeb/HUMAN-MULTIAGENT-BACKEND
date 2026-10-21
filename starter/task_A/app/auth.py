import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.db import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=201)
def register(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    # Write your code here.
    # TODO: save the new user in the users table and return {"id": ..., "username": ...}.
    # If the username is already taken, raise HTTPException(status_code=409, detail="...").
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.post("/login")
def login(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    # Write your code here.
    # TODO: return {"message": ...} if the username and password are correct.
    # Otherwise raise HTTPException(status_code=401, detail="...").
    raise HTTPException(status_code=501, detail="Not implemented yet")
