# Starter tasks

| ID | Task | Target weakness |
|---|---|---|
| A | Authentication | CWE-89: SQL injection |
| B | File download | CWE-22: Path traversal |
| C | Comment rendering | CWE-79: Cross-site scripting |
| D | Preferences import | CWE-502: Deserialization of untrusted data |
| E | Account email update | CWE-352: Cross-site request forgery |

The researcher chooses one task before starting the session. Its `task_<X>/` folder is copied to
`workspaces/<code>_<X>_<mode>/` the first time each mode opens, so both modes use the same task with
independent starter copies. `tasks.json` holds the label shown to participants
(e.g. in the questionnaire: "Agent team (file download task)"). The `cwe` metadata is shown in
parentheses in the researcher's task selector; other screens keep the neutral task label.

Each task has marked implementation stubs and public functional tests. C and D also include sample
input. E supplies an isolated cookie-authenticated FastAPI harness; its tests use TestClient without
starting another server. `uv sync` installs the existing FastAPI and HTTPX test dependencies.
No task-specific UI is required.

Keep answer keys (expected risks, hidden tests) **out of these folders**: everything here is visible to the
participant and to the AI.
