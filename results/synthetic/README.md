# Synthetic results for analysis rehearsal

These records are fabricated. They are not participant responses, observations, pilot data or evidence that either AI mode performs better. Never combine them with results/*.csv or report their figures as study findings.

The generator uses seed 20261107 and creates 40 SYN-prefixed mock participants. Every ordered pair of the five tasks appears with each mode first. All mock parts are marked complete so the existing analysis can exercise its paired-data path. Functional tests, finding decisions, mitigation states and optional questionnaire answers vary across records. Open feedback is blank.

Regenerate with `uv run python generate_mock_results.py`. The script reads only the headers of the current real exports and writes only inside this directory.

Analyze with `uv run python analyze_results.py --input results/synthetic --output results/synthetic/analysis --synthetic`. Different tasks are assigned to each mode, so paired differences are descriptive and do not isolate a mode effect.
