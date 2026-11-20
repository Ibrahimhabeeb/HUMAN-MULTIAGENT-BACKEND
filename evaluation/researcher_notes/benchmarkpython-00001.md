# Private ground truth: BenchmarkPython 00001

Do not place this file in an agent workspace or show it before both reviews are complete.

Source: OWASP Benchmark for Python v0.1, `testcode/BenchmarkTest00001.py`.

| Ground-truth field | Value |
| --- | --- |
| Category | Path traversal |
| Expected result | Real vulnerability |
| CWE | CWE-22 |
| Relevant flow | A cookie value is URL-decoded and used to form a file path before the file is opened. |

## Record manually

| Condition | Identified a concrete finding? | Correct CWE/category? | Correct code area? | Invented unrelated finding? | Notes |
| --- | --- | --- | --- | --- | --- |
| Agent Team | | | | | |
| Single Assistant | | | | | |

Interpret this as one illustrative reviewer case, not a precision/recall benchmark or a full evaluation of the
multi-agent workflow.
