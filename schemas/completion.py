from pydantic import BaseModel, Field


class CompletionRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=100_000)
    line: int = Field(ge=1)
    column: int = Field(ge=1)


class CompletionItem(BaseModel):
    name: str
    type: str
    description: str


class CompletionResult(BaseModel):
    items: list[CompletionItem]
