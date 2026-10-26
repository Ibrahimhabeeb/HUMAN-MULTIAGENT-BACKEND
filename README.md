# Secure Coding Room: backend

The FastAPI backend for the study that compares a team of AI agents with a single AI assistant for secure coding.
Each browser tab has its own participant session: information sheet, consent, two parts (one in each mode)
and a questionnaire. Different participants can work at the same time.

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
| `TEST_TIMEOUT_SECONDS` | `60` | How long one click on Run tests may take |
| `DATABASE_URL` | `sqlite:///./data/app.db` | Where everything except code is stored. The study uses PostgreSQL: `postgresql+psycopg://USER:PASSWORD@localhost:5432/HUMANAGENTDB` |

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

The tests never call the AI model and never touch the study database: each test uses its own throwaway SQLite
database. The PostgreSQL-only analysis views are not covered by them.

## Database

With PostgreSQL, the app brings the database up to date itself when it starts, using the Alembic migrations in
`migrations/versions/`: the tables, then the analysis views. After changing a model, add a migration:

```
uv run alembic revision --autogenerate -m "what changed"
uv run alembic upgrade head
```

The views give the study's statistics directly (open them in pgAdmin under Schemas > public > Views):

| View | One row per | What it gives |
|---|---|---|
| `v_part_summary` | part | Time on task, reviews, test runs, typed messages, decisions, and the results below |
| `v_vulnerability_outcomes` | team part | Findings proposed, accepted, rejected, fixed (mitigation implemented), still without a fix |
| `v_unit_test_results` | part, both modes | The task's unit tests passed and failed in the latest run: after Finish, the final result |
| `v_survey` | answer | Each answer with its question, its number (`value_num`) and `score` (reversed if `reverse_scored`) |
| `v_survey_paired` | participant and question | The per-mode questions, team and single side by side |

`uv run python export.py` writes `results/survey.csv` and, with PostgreSQL, each view as `results/<view>.csv`,
without pilots or withdrawn participants.

## Before the study

- `content/information_sheet.md` and `content/consent.md` are drafts. Replace them with the approved text and
  change their `<!-- version: ... -->` line.
- Add `content/questionnaire.json` with the approved questions (format below). Until it exists, the
  questionnaire screen says it isn't ready. The server checks the file when it starts.
- Run tests runs the participant's code on this machine. Use an API key that is only for the study and has a
  spending limit, and keep other secrets off the machine.

## A session

Everything happens in the browser. The frontend asks `GET /study/state` which screen to show.

The frontend first calls `POST /study/session` with `{"mode": "team"}` (or `"single"`). It keeps the returned
random token in `sessionStorage` and sends it as `X-Session-Token` on subsequent study, workspace, chat and
approval requests. Missing, unknown or revoked tokens receive 401; there is no global active-participant fallback.
Public information/consent content and health checks do not expose participant data.

1. **Start**: choose the task, then `POST /study/start` with `{"pilot": false, "task_id": "A"}`
   (`A` = authentication, `B` = file download, `C` = comment rendering,
   `D` = preferences import, `E` = account email update; defaults to `A`). Nothing is stored yet.
2. **Information sheet**, then **consent**: `POST /study/continue`, then `POST /study/consent`. Only now is the
   participant ID created: `P01`, `P02`... or `X01`... for pilots.
3. **Part 1**: the chosen task, in the mode chosen with `POST /study/mode` (`team` or `single`).
4. **Done**: `POST /study/done`. Continue with the other mode for the same task in part 2,
   using a fresh starter copy. Each mode keeps its own code, chat, approvals, tests and snapshots.
5. **Questionnaire**: `GET /study/questionnaire`, then `POST /study/questionnaire`.
6. **Thank you**, then **Finish**: `POST /study/finish`.

**Restart for new participant**
(`POST /study/restart`) ends the session at any point and keeps the data, marking the participant incomplete.
Finish and Restart revoke the old token and return a fresh token in the `X-Session-Token` response header;
the frontend replaces its stored token. The same tab defaults to the previous ending mode for the next
participant. A fresh tab defaults to team; the researcher can select either starting mode.

Before consent, setup is held only in server memory, keyed by the token hash. After consent, `study_sessions`
stores only the SHA-256 token hash and participant code. A server restart preserves consented sessions but
discards pre-consent setup. Run one backend worker while pre-consent sessions use process memory.
Tokens and hashes are not added to questionnaire answers or interaction events.

Closing a tab clears its browser token; it does not automatically delete or complete saved study data.
Open a fresh study tab for a different participant rather than duplicating a tab with an existing session,
because browsers can copy sessionStorage when duplicating tabs. Existing participant records without a token
are preserved, but are never automatically assigned to a new browser.

During a part:

| | Endpoints |
|---|---|
| Files | `GET /workspace/files`, `GET`/`PUT`/`DELETE /workspace/files/{path}`, `POST /workspace/folders`, `POST /workspace/files/rename` |
| Chat | `GET /chat`, `GET`/`POST /chat/{thread}` (`team` or `assistant`), `POST /chat/next` (team mode: the next agent on the route answers) |
| Ready for review / Review updated code | `POST /chat/review` |
| Finding follow-ups (team mode) | `POST /chat/follow-ups/{message_id}` |
| Run tests | `POST /workspace/tests/run` |
| Approvals | `GET /approvals`, `POST /approvals/{id}/decide` |
| Shared security state (team mode) | `GET /workspace/state`, `POST`/`PATCH`/`DELETE /workspace/state/{category}/...` |
| Notes (single mode) | `GET`/`PUT /workspace/notes` |

Fixes, vulnerabilities, assumptions and test files wait for approval in the chat; the Approvals pane holds
suggested risks and decision history. Risks go straight into the shared security state as suggestions.
In team mode, the first message runs the Planner and then the Threat Modeller automatically in one request.
The Planner gives implementation steps; the Threat Modeller receives that plan and analyses potential attacks,
impact and expected secure behaviour. Neither the handoff nor reading project files needs a confirmation.
Each reply is saved before the next agent starts; `POST /chat/next` can retry an interrupted route.
In single mode, fix/test approvals are decision records only: they never create or update shared security state.
Approving a fix never changes application code in either mode; the human writes it themselves.
Approving a vulnerability queues the Reviewer's fix suggestion and the Verifier's test proposal together.
Their progress is persisted in chat messages, so refresh resumes queued work without duplicating model calls.
The Verifier reads existing Python files under `tests/` and can propose extending them. Files change only when
a test proposal is approved; production fixes are always typed by the human.

## Researcher scripts

```
uv run python export.py         # writes results/survey.csv, leaving out pilots and withdrawn participants
uv run python withdraw.py P07   # deletes everything stored for P07; the ID is never given out again
```

## Where the data goes

None of it is committed to git.

| Location | Contents |
|---|---|
| The database (`DATABASE_URL`) | Participants, hashed session tokens, consent records, the event log, approvals, chat messages, the security state (one table per section) and unit test results, the questions and the answers |
| `workspaces/<ID>_<task>_<mode>/` | An independent code workspace for each mode |
| `snapshots/<ID>_<task>_<mode>/` | That mode's code at each review, test run and Done |
| `results/` | Exports |

Older `<ID>_<task>/` folders remain readable in their existing sessions. Previously assigned parts are
not rewritten or deleted; an older session that already opened two different tasks keeps those records.

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
