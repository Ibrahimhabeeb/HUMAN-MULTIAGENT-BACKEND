# Starter tasks

| ID | Task | Target weakness |
|---|---|---|
| A | Authentication | CWE-89: SQL injection |
| B | File download | CWE-22: Path traversal |
| C | Comment rendering | CWE-79: Cross-site scripting |
| D | Preferences import | CWE-502: Deserialization of untrusted data |
| E | Account email update | CWE-352: Cross-site request forgery |
| F | Document access | CWE-639: Authorization bypass through user-controlled key |
| G | Account recovery audit | CWE-532: Sensitive information in logs |

The researcher chooses the first task before starting the session. After finishing Part 1,
the participant chooses a different task for Part 2, which uses the other mode. Each task's
`task_<X>/` folder is copied to an independent `workspaces/<code>_<X>_<mode>/` folder.
`tasks.json` holds the label shown to participants
(e.g. in the questionnaire: "Agent team (file download task)"). The `cwe` metadata is shown in
parentheses in both task selectors; the editor and questionnaire keep the neutral task label.

Each task has marked implementation stubs and public functional tests. C and D also include sample
input. E uses an `Account` object and a server-side session dictionary; its tests call the update
function directly, without HTTP or a separate server. F checks document ownership, and G records
recovery events without exposing tokens. No task-specific UI is required.

Keep answer keys (expected risks, hidden tests) **out of these folders**: everything here is visible to the
participant and to the AI.
