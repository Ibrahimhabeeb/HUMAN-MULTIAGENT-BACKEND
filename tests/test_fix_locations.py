import pytest
from pydantic import ValidationError

from agents.context import AgentContext
from agents.fix_guidance import FIX_GUIDANCE
from agents.roles import ASSISTANT_PROMPT, team_prompt
from agents.tools import make_tools
from schemas.approval import FixSuggestion

FIX = {
    "vulnerability": "SQL injection",
    "file": "app/auth.py",
    "location": "login(), replace the SELECT query at line 12",
    "code": 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
    "why": "Parameters keep user input separate from SQL.",
}


def test_file_and_location_guidance_is_for_the_single_assistant():
    assert FIX_GUIDANCE in ASSISTANT_PROMPT
    assert FIX_GUIDANCE not in team_prompt("reviewer")  # the Code Reviewer writes its fixes into the code itself


@pytest.mark.parametrize("changes", [
    {"file": ""}, {"file": "   "}, {"file": "../auth.py"}, {"file": "/app/auth.py"},
    {"file": "C:/app/auth.py"}, {"location": ""}, {"location": "   "},
])
def test_fixes_require_a_workspace_path_and_non_empty_location(changes):
    with pytest.raises(ValidationError):
        FixSuggestion.model_validate({**FIX, **changes})


def test_agent_can_correct_a_missing_location_before_human_sees_the_fix():
    context = AgentContext(files={"app/auth.py": ""}, state=None)
    tool = next(t for t in make_tools(context, "assistant") if t.name == "suggest_fix")
    assert tool.invoke({**FIX, "location": ""}).startswith("Not recorded")
    assert context.proposals == []
    assert tool.invoke(FIX) == "Recorded. It waits for the developer's approval."
    assert context.proposals[0].proposal["file"] == "app/auth.py"
    assert context.proposals[0].proposal["location"] == FIX["location"]
