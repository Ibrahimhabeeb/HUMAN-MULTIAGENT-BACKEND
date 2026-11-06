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

The study output goes to `results/analysis/study/`; the pilot output goes to `results/analysis/pilot/`. The two cohorts are filtered separately even when the export contains both. Each `summary.json` records its `cohort` and `pilot_sample_only` value. `--input` and `--output` can override the default paths.

SciPy is optional. The different-task study analysis reports descriptive results without Wilcoxon mode-effect p-values. If SciPy is installed, the script can still calculate an exploratory Wilcoxon result for older pilots that repeated the same task, provided there are enough pairs.

`analyze_results.py` reads the five `v_*.csv` files in `results/` and writes:

| File | Contents |
| --- | --- |
| `paired_activity.csv` | One row per eligible participant, showing team and single activity side by side. |
| `paired_parts.csv` | One row per participant with final provided-task-test outcomes for both modes. |
| `paired_survey.csv` | One row per answered paired question and participant. |
| `summary.json` | Inclusion counts, task and mode-order counts, descriptive comparisons, exploratory tests, team-only shared-state ratings, and team security-state totals. |
| `report.md` | A readable sample report with participant-level task-test outcomes, questionnaire medians, and interpretation limits. |

For study results, an eligible participant is non-pilot, complete, and has exactly one submitted workspace in each mode on **different tasks**. Earlier same-task sessions are excluded from the study analysis. For pilot demonstrations, a pilot with both task parts submitted is eligible even if the session was marked incomplete before the questionnaire; earlier same-task pilots remain visible as legacy examples. Missing survey answers stay missing. A participant with unrun or missing task tests remains in the sample but is excluded from the functional-test comparison. Skipped or `Not applicable` survey responses are omitted from that question's paired comparison. Check each comparison's `n`.

For numeric results, the script reports medians, within-participant differences (`team - single`), and counts. It also records each task's assignment to each mode and shows functional results by task. Because the participant chooses Task 2, task difficulty and mode can be confounded; these descriptive differences are **not estimates of a mode effect**. The script does not calculate Wilcoxon or McNemar mode-effect p-values for different-task sessions. The older same-task pilot examples may still show an exploratory paired test when enough comparable pairs exist, but those attempts are subject to learning effects. A future inferential analysis needs a documented task-assignment design and enough observations per task and order.

The provided task tests measure whether specific requirements passed; they do not establish that code has no vulnerabilities. `v_vulnerability_outcomes.csv` records **team-mode security-state activity**. Its `fixed` count reflects recorded mitigation status and is not independent evidence that a vulnerability was eliminated. For a team-versus-single vulnerability comparison, assess both final code snapshots using the same criteria and keep that assessment separate from the participant exports. The script does not yet compute that outcome because no independent assessment CSV exists.

Questionnaire items about unnecessary complexity and wariness are negatively worded. Read their scores in the direction of their original wording; do not combine them with positive items into a scale without a documented scoring decision. Team-only shared-state questions and open comments should be reported descriptively or thematically, not as paired mode comparisons.

The current `results/` exports contain pilot data only. The pilot output is **illustrative sample data for the supervisor**, not a study result. There is currently too little paired questionnaire data for Wilcoxon testing.
