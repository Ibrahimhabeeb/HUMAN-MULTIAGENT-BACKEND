# Researcher case studies

This folder is for small, manual technical case studies. It is not part of Study Mode, the participant task menu,
the consent flow, or the participant-results export.

Each case has two parts:

- `cases/`: material and a neutral prompt that may be shown to an agent.
- `researcher_notes/`: the private ground truth used only after the review is complete.

## Manual protocol

1. Start a fresh **pilot** workspace for Team mode and another for Single mode. Do not use a real participant session.
2. Give each condition the same source snapshot and the prompt in that case's `manifest.json`.
3. Do not show the original OWASP filename, route/category name, expected-results CSV, or researcher notes to either
   condition. Those reveal the answer.
4. Save the two replies and record whether each condition identified a concrete vulnerability, named the correct CWE,
   and located the relevant code.
5. Only then read the matching private researcher note and describe the comparison as an illustrative case study.

This is a supplementary technical check of review behaviour. It does not evaluate the full human-agent study and must
not be combined with participant data.
