from typing import Literal

from pydantic import BaseModel, Field, model_validator

from schemas.study import Mode

QuestionType = Literal["scale", "choice", "text"]
AskedFor = Literal["each_mode", "team", "once"]  # both modes side by side, the agent team only, or once
Condition = Literal["team", "single", "none"]

TEXT_HINT = "Please don't include names or other personal details."
MAX_ANSWER_CHARS = 2000


class Question(BaseModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    type: QuestionType
    text: str = Field(min_length=1)
    options: list[str] = []  # choice questions only

    @model_validator(mode="after")
    def _options_only_for_choices(self) -> "Question":
        if (self.type == "choice") != bool(self.options):
            raise ValueError(f"{self.key}: a choice question needs options, and only choice questions have them")
        return self


class Section(BaseModel):
    title: str
    intro: str | None = None
    asked_for: AskedFor
    questions: list[Question] = Field(min_length=1)


class Scale(BaseModel):
    min: int = 1
    max: int = 7
    min_label: str = "Strongly disagree"
    max_label: str = "Strongly agree"


class Questionnaire(BaseModel):
    # Read from content/questionnaire.json, so the wording approved for the ethics application is used as it is.
    version: str
    scale: Scale = Scale()
    sections: list[Section] = Field(min_length=1)

    @model_validator(mode="after")
    def _keys_are_unique(self) -> "Questionnaire":
        keys = [question.key for section in self.sections for question in section.questions]
        if len(keys) != len(set(keys)):
            raise ValueError("Every question needs its own key")
        return self


class ModeLabel(BaseModel):
    mode: Mode
    label: str  # e.g. "Agent team (file download task)"


class QuestionnaireOut(Questionnaire):
    modes: list[ModeLabel]  # in the order the participant used them
    text_hint: str = TEXT_HINT  # shown with every open-answer box


class Answer(BaseModel):
    condition: Condition
    item: str
    value: int | str | None = None


class QuestionnaireAnswers(BaseModel):
    answers: list[Answer] = Field(default=[], max_length=500)  # questions left out count as skipped
