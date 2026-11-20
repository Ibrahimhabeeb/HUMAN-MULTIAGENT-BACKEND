# Study results analysis

Run from `backend/` after exporting current PostgreSQL data. For the final study cohort:

```bash
uv run python export.py
uv run python analyze_results.py
```

For a **pilot-only supervisor demonstration**, run:

```bash
uv run python export.py --include-pilots
uv run python analyze_results.py --pilots
```

The study output goes to `results/analysis/study/`; the pilot output goes to `results/analysis/pilot/`. The two cohorts are filtered separately even when the export contains both. Each `summary.json` records its `cohort` and `pilot_sample_only` value. `--input` and `--output` can override the default paths. Restart the backend or run `uv run alembic upgrade head` to add the security-state views, then rerun `export.py` before analysing older exports.

SciPy is optional. The different-task study analysis reports descriptive results without Wilcoxon mode-effect p-values. If SciPy is installed, the script can still calculate an exploratory Wilcoxon result for older pilots that repeated the same task, provided there are enough pairs.

`analyze_results.py` reads the seven `v_*.csv` files in `results/`: the original part, test, vulnerability and two survey views, plus `v_security_state_inventory.csv` and `v_security_state_decisions.csv`. It writes:

| File | Contents |
| --- | --- |
| `paired_activity.csv` | One row per eligible participant, showing team and single activity side by side. |
| `paired_parts.csv` | One row per eligible participant with unit, security and combined test totals, passed/failed counts, pass rates and all-passed flags for team and single modes. The existing `team_pass_rate` and `single_pass_rate` columns refer to unit tests. |
| `paired_survey.csv` | One row per answered paired question and participant. |
| `security_state_parts.csv` | One eligible team part per row: findings, assumptions, risks, mitigations and accepted-finding linkage. |
| `security_state_decisions.csv` | One state-related agent action per row, including its status and human decision time where applicable. |
| `summary.json` | Inclusion counts, task and mode-order counts, descriptive comparisons, exploratory tests, team-only ratings, state inventory totals and action-specific decisions. |
| `report.md` | One readable report covering unit, security and combined test results, activity, questionnaire answers, vulnerabilities, mitigations and shared security state. Section headings identify the input and derived CSVs. |

`results/` is Git-ignored because it can contain participant data. The new generated CSVs and reports are local outputs; regenerate them after switching branches or merging rather than committing real exports.

The sample-data generator and stored example exports have been removed. Export and analysis exclude participant
codes beginning with `SYN`, so old sample material cannot enter study or pilot results. The production stack
starts with a fresh PostgreSQL volume; existing local records are preserved separately. See `DEPLOYMENT.md` for
export and analysis commands against the hosted database.

Hidden security tests run on the final snapshot at Finish part in both modes. Each run is saved in `events` as `security_tests_run`, including the workspace, snapshot, suite version, counts and individual outcomes. The `v_unit_test_results` database view selects the latest assessment for each workspace and appends its security and combined results to the existing unit-test columns. `export.py` exports this view directly. `analyze_results.py` reads it to produce `paired_parts.csv`. Separate security-test CSVs are no longer required by this flow.

The report gives the total passed and total expected tests, the overall pass rate, the median submission pass rate and the number of submissions passing all tests for each group and mode. A combined pass rate is `(unit passed + security passed) / (unit total + security total)`. The unit total contains the provided task tests. Security runs with missing results, errors, skipped tests or unrun tests have no security or combined score. Older exports without security columns remain readable with those scores blank. Paired summaries use participants with valid results in both modes for the relevant group.

For study results, an eligible participant is non-pilot, complete, and has exactly one submitted workspace in each mode on **different tasks**. Earlier same-task sessions are excluded from the study analysis. For pilot demonstrations, a pilot with both task parts submitted is eligible even if the session was marked incomplete before the questionnaire; earlier same-task pilots remain visible as legacy examples. Missing survey answers stay missing. A participant with unrun or missing task tests remains in the sample but is excluded from the functional-test comparison. Skipped or `Not applicable` survey responses are omitted from that question's paired comparison. Check each comparison's `n`.

For numeric results, the script reports medians, within-participant differences (`team - single`), and counts. It also records each task's assignment to each mode and shows functional results by task. Because the participant chooses Task 2, task difficulty and mode can be confounded; these descriptive differences are **not estimates of a mode effect**. The script does not calculate Wilcoxon or McNemar mode-effect p-values for different-task sessions. The older same-task pilot examples may still show an exploratory paired test when enough comparable pairs exist, but those attempts are subject to learning effects. A future inferential analysis needs a documented task-assignment design and enough observations per task and order.

The provided task tests measure whether specific requirements passed; they do not establish that code has no vulnerabilities. `v_vulnerability_outcomes.csv` records **team-mode security-state activity**. `v_security_state_inventory.csv` adds assumptions, risks, mitigation status and accepted-vulnerability-to-mitigation linkage; `v_security_state_decisions.csv` records the agent action, disposition and decision time. Assumptions and risks come from the Threat Modeller: assumptions require approval, while risks are recorded as suggestions. There is no generic mitigation-proposal approval: a Code Reviewer-written fix follows the developer's separate fix choice; `mark_resolved` records a decision to mark a mitigation implemented. Developer-added mitigations and vulnerability findings bypass agent approval.

These measures describe state use and continuity, including the developer's separate fix-ownership choice after an accepted finding. In particular, `fixed` means that an implemented mitigation was **recorded**. The schema does not link risks directly to vulnerabilities. Hidden security-test outcomes are assessed on the final snapshots in both modes and reported as pass rates. Residual vulnerability counts would require a separate code assessment using consistent criteria.

Questionnaire items about unnecessary complexity and wariness are negatively worded. Read their scores in the direction of their original wording; do not combine them with positive items into a scale without a documented scoring decision. Team-only shared-state questions and open comments should be reported descriptively or thematically, not as paired mode comparisons.

If the export contains only pilots, the study cohort will have no eligible pairs. Pilot output is **illustrative sample data for the supervisor**, not a final study result; check the eligible-pair count before interpreting any comparison.
