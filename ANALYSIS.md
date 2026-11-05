# Study results analysis

Run from `backend/` after exporting current PostgreSQL data. For the final study cohort:

```bash
uv run python export.py
uv run --with scipy python analyze_results.py
```

For a **pilot-only supervisor demonstration**, run:

```bash
uv run python export.py --include-pilots
uv run --with scipy python analyze_results.py --pilots
```

The study output goes to `results/analysis/study/`; the pilot output goes to `results/analysis/pilot/`. The two cohorts are filtered separately even when the export contains both. Each `summary.json` records its `cohort` and `pilot_sample_only` value. `--input` and `--output` can override the default paths.

SciPy is an analysis-only dependency requested by the second command. It is not installed in the backend's normal `.venv`, so running `python analyze_results.py` directly writes descriptive statistics but leaves Wilcoxon p-values empty. The script loads SciPy at runtime to keep the editor from reporting an unresolved optional import.

`analyze_results.py` reads the five `v_*.csv` files in `results/` and writes:

| File | Contents |
| --- | --- |
| `paired_activity.csv` | One row per eligible participant, showing team and single activity side by side. |
| `paired_parts.csv` | One row per participant with final provided-task-test outcomes for both modes. |
| `paired_survey.csv` | One row per answered paired question and participant. |
| `summary.json` | Inclusion counts, task and mode-order counts, descriptive comparisons, exploratory tests, team-only shared-state ratings, and team security-state totals. |
| `report.md` | A readable sample report with participant-level task-test outcomes, questionnaire medians, and interpretation limits. |

For study results, an eligible participant is non-pilot, complete, and has exactly one submitted workspace in each mode on the same task. For pilot demonstrations, a pilot with both task parts submitted is eligible even if the session was marked incomplete before the questionnaire; its missing survey answers stay missing. A participant with unrun or missing task tests remains in the sample but is excluded from the functional-test comparison. Skipped or `Not applicable` survey responses are omitted from that question's paired comparison. Check each comparison's `n`.

For numeric paired results, the script reports the median in each mode, mean within-participant difference (`team - single`), and counts favouring each mode or tied. With SciPy installed, it also reports a two-sided Wilcoxon signed-rank p-value for comparisons with at least five pairs and a nonzero difference. These p-values are **exploratory and unadjusted**; do not interpret a collection of small p-values as separate confirmed findings. For the yes/no outcome of passing every provided task test, `summary.json` reports an exact McNemar paired test when discordant pairs exist. Show the actual differences and sample sizes alongside p-values.

The provided task tests measure whether specific requirements passed; they do not establish that code has no vulnerabilities. `v_vulnerability_outcomes.csv` records **team-mode security-state activity**. Its `fixed` count reflects recorded mitigation status and is not independent evidence that a vulnerability was eliminated. For a team-versus-single vulnerability comparison, assess both final code snapshots using the same criteria and keep that assessment separate from the participant exports. The script does not yet compute that outcome because no independent assessment CSV exists.

Questionnaire items about unnecessary complexity and wariness are negatively worded. Read their scores in the direction of their original wording; do not combine them with positive items into a scale without a documented scoring decision. Team-only shared-state questions and open comments should be reported descriptively or thematically, not as paired mode comparisons.

The current `results/` exports contain pilot data only. The pilot output is **illustrative sample data for the supervisor**, not a study result. There is currently too little paired questionnaire data for Wilcoxon testing.
