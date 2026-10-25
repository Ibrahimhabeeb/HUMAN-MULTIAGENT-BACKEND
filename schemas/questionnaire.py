from typing import Literal

from pydantic import BaseModel, Field, model_validator

from schemas.study import Mode

QuestionType = Literal["scale", "number", "choice", "text"]
AskedFor = Literal["each_mode", "team", "once"]  # both modes side by side, the agent team only, or once
Condition = Literal["team", "single", "none"]

TEXT_HINT = "Please don't include names or other personal details."
MAX_ANSWER_CHARS = 2000


class Scale(BaseModel):
    min: int = 1
    max: int = 7
    min_label: str = "Strongly disagree"
    max_label: str = "Strongly agree"


class Question(BaseModel):
    number: int = Field(ge=1)
    key: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    type: QuestionType
    text: str = Field(min_length=1)
    scale: Scale | None = None  # scale and number questions only
    allow_not_applicable: bool = False
    options: list[str] = Field(default_factory=list)  # choice questions only

    @model_validator(mode="after")
    def _validate_response_shape(self) -> "Question":
        if (self.type == "choice") != bool(self.options):
            raise ValueError(f"{self.key}: a choice question needs options, and only choice questions have them")
        if (self.type in {"scale", "number"}) != (self.scale is not None):
            raise ValueError(f"{self.key}: only scale and number questions need a scale")
        if self.allow_not_applicable and self.type != "scale":
            raise ValueError(f"{self.key}: only scale questions can allow Not applicable")
        return self


class Section(BaseModel):
    title: str
    show_title: bool = True  # titles are metadata too; the study form can keep a question-led flow.
    intro: str | None = None
    asked_for: AskedFor
    questions: list[Question] = Field(min_length=1)


class Questionnaire(BaseModel):
    # Read from content/questionnaire.json, so the wording approved for the ethics application is used as it is.
    version: str
    sections: list[Section] = Field(min_length=1)

    @model_validator(mode="after")
    def _keys_are_unique(self) -> "Questionnaire":
        keys = [question.key for section in self.sections for question in section.questions]
        if len(keys) != len(set(keys)):
            raise ValueError("Every question needs its own key")
        numbers = [question.number for section in self.sections for question in section.questions]
        if sorted(numbers) != list(range(1, len(numbers) + 1)):
            raise ValueError("Question numbers must run from 1 without gaps")
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
