# Hidden security assessment

The seven suites in `security_tests/` are private assessment code. They are kept outside `starter/`, participant workspaces, snapshots and agent context.

Each task part is assessed after Finish part has saved its final snapshot. The assessment uses a disposable copy of the submitted `app/` directory, the server's Python, the existing test timeout and an environment with model credentials removed. Run tests, review and Test/Verifier interactions run the participant-visible tests. The private results are saved as `security_tests_run` events and are available through the analysis exports.

The manifest fixes the expected test counts and records a suite version. Each run also records a hash of its manifest and selected suite. Technical errors, timeouts, skipped tests and missing assessments cannot count as all tests passed. The assessment subprocess has the same operating-system isolation limits as the existing functional-test runner.

| Task | Target | Cases |
| --- | --- | ---: |
| A | SQL injection and credential handling | 12 |
| B | File-download path traversal | 8 |
| C | XSS in author and comment text | 12 |
| D | Executable deserialisation and invalid preferences | 18 |
| E | Missing, incorrect and cross-session request tokens | 11 |
| F | Access to another user's documents | 10 |
| G | Recovery tokens in log messages, arguments and extra fields | 6 |

`uv run python export.py` exports the `v_unit_test_results` database view, including the latest recorded security assessment and combined unit/security totals for each workspace. The normal participant and pilot filters apply. `analyze_results.py` writes unit, security and combined counts, pass rates and all-passed flags into `paired_parts.csv`, and reports all three groups in the test-results section of `report.md`. Historical submissions without an assessment have blank security and combined scores.

These tests exercise the documented task contracts. For Task B, out-of-directory requests may raise `OSError` (including `PermissionError` or `FileNotFoundError`) or `ValueError`. Password checks detect plaintext storage but do not establish the strength of every possible hashing scheme. Log checks cover the full recovery token and identifiable prefix/suffix fragments.
