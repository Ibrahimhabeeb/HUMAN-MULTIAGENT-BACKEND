# Secure Coding Room: backend

The FastAPI backend for the study that compares a team of AI agents with a single AI assistant for secure coding.
It runs one participant session at a time: information sheet, consent, two parts (one in each mode) and a
questionnaire.

## Setup

Needs Python 3.13 and [uv](https://docs.astral.sh/uv/).

```
uv sync
```

Create a `.env` file (it is never committed):

```
LLM_MODEL=openai:gpt-4.1-mini
LLM_API_KEY=sk-...
```

Optional settings, in `.env` or as environment variables:

| Setting | Default | Meaning |
|---|---|---|
| `PART_TIME_LIMIT_MINUTES` | `25` | Time limit for each part (confirm after the pilot) |
| `TEST_TIMEOUT_SECONDS` | `60` | How long one click on Run tests may take |
| `DATABASE_URL` | `sqlite:///./data/app.db` | Where everything except code is stored |

## Run

```
uv run python main.py
```

The API runs on http://127.0.0.1:8000, with interactive docs at http://127.0.0.1:8000/docs.
It accepts requests from the frontend on port 5001 (or 5000).

## Check

```
uv run pytest
uv run ruff check .
```

The tests never call the AI model and never touch `data/app.db`.

## Before the study

- `content/information_sheet.md` and `content/consent.md` are drafts. Replace them with the approved text and
  change their `<!-- version: ... -->` line.
- Add `content/questionnaire.json` with the approved questions (format below). Until it exists, the
  questionnaire screen says it isn't ready. The server checks the file when it starts.
- Run tests runs the participant's code on this machine. Use an API key that is only for the study and has a
  spending limit, and keep other secrets off the machine.

## A session

Everything happens in the browser. The frontend asks `GET /study/state` which screen to show.

1. **Start**: `POST /study/start` with `{"pilot": false}`. Nothing is stored yet.
2. **Information sheet**, then **consent**: `POST /study/continue`, then `POST /study/consent`. Only now is the
   participant ID created: `P01`, `P02`... or `X01`... for pilots.
3. **Part 1**: task A, in the mode chosen with `POST /study/mode` (`team` or `single`).
4. **Done**: `POST /study/done`. Switching to the other mode starts part 2 with task B.
5. **Questionnaire**: `GET /study/questionnaire`, then `POST /study/questionnaire`.
6. **Thank you**, then **Finish**: `POST /study/finish`.

A part also ends when its time runs out, as if Done was clicked. **Restart for new participant**
(`POST /study/restart`) ends the session at any point and keeps the data, marking the participant incomplete.
Each participant starts in the mode the previous one ended in, so the starting mode alternates.

During a part:

| | Endpoints |
|---|---|
| Files | `GET /workspace/files`, `GET`/`PUT`/`DELETE /workspace/files/{path}`, `POST /workspace/folders`, `POST /workspace/files/rename` |
| Chat | `GET /chat`, `GET`/`POST /chat/{thread}`, `POST /chat/consult/{agent}` (team mode) |
| Ready for review | `POST /chat/review` |
| Run tests | `POST /workspace/tests/run` |
| Approvals | `GET /approvals`, `POST /approvals/{id}/decide` |
| Shared security state (team mode) | `GET /workspace/state`, `POST`/`PATCH`/`DELETE /workspace/state/{category}/...` |
| Notes (single mode) | `GET`/`PUT /workspace/notes` |

The agents never change anything themselves. Each proposal (a risk, a fix, a test file...) waits in
`/approvals` until the participant approves or rejects it.

## Researcher scripts

```
uv run python export.py         # writes results/survey.csv, leaving out pilots and withdrawn participants
uv run python withdraw.py P07   # deletes everything stored for P07; the ID is never given out again
```

## Where the data goes

None of it is committed to git.

| Location | Contents |
|---|---|
| `data/app.db` | Participants, consent records, the event log, approvals, chat messages, questionnaire answers |
| `workspaces/<ID>_<task>/` | The code of each part |
| `snapshots/<ID>_<task>/` | The code at each review, test run and Done |
| `results/` | Exports |

## Questionnaire format

```json
{
  "version": "v1",
  "scale": {"min": 1, "max": 7, "min_label": "Strongly disagree", "max_label": "Strongly agree"},
  "sections": [
    {
      "title": "Section title",
      "asked_for": "each_mode",
      "questions": [{"key": "statement_one", "type": "scale", "text": "A statement rated for each mode"}]
    },
    {
      "title": "Another section",
      "asked_for": "once",
      "questions": [
        {"key": "choice_one", "type": "choice", "text": "A question", "options": ["Option A", "Option B"]},
        {"key": "open_one", "type": "text", "text": "An open question"}
      ]
    }
  ]
}
```

- `asked_for` is one of:
  - `each_mode`: asked for both modes, side by side, each labelled with its task.
  - `team`: asked about the agent team only.
  - `once`: asked a single time.
- `type` is `scale`, `choice` or `text`.
- Every question can be skipped. Each answer is stored with the participant ID only.

## Code layout

| Folder | Contents |
|---|---|
| `api/` | The HTTP routes |
| `services/` | Study flow, workspaces, security state, approvals, chat, test runner, questionnaire |
| `agents/` | Agent roles and prompts, their tools, and the team and single-assistant workflows |
| `models/`, `schemas/` | Database tables, and request and response shapes |
| `content/` | Text shown to participants |
| `starter/` | Tasks A and B, copied into each participant's workspace |
