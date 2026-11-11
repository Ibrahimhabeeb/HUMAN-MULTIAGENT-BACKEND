# Task: Account recovery audit

Implement `record_recovery_attempt()` in `app/audit.py`. An account-recovery attempt
should leave a useful audit event without exposing its recovery token in logs.

## What to implement

`record_recovery_attempt(logger, account_id, recovery_token, succeeded) -> None`

- `logger` is a Python `logging.Logger` supplied by the caller.
- `account_id` is the numeric account ID and may be logged.
- `recovery_token` is secret. Do not log it, including in structured log arguments.
- `succeeded` says whether the attempt succeeded.

Write one INFO-level event containing the account ID and the outcome (`succeeded` or
`failed`). Do not write the token, a token fragment, or the complete request to the log.
Do not create a log file or configure logging; use the supplied logger.

The tests capture log records in memory. No account-recovery UI or HTTP route is required.
Click **Run tests** to run the tests in `tests/`.
