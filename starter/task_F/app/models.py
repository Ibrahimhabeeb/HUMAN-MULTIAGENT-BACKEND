from dataclasses import dataclass


@dataclass(frozen=True)
class Document:
    id: int
    owner_id: int
    title: str
    body: str
