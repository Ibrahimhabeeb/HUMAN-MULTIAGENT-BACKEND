# Task: Account email update

A signed-in user wants to change their account email. Implement the update function in
`app/account.py`. You do not need to build login, HTTP routes or a browser interface.

## What to implement

`update_email(account, session, email, request_token) -> dict[str, str]`

- `account` is the signed-in user's account dictionary, initially containing an `email`.
- `session` is that user's server-side session dictionary. It contains a `request_token`.
- `email` is the new email address.
- `request_token` is the token submitted with the update; it may be missing (`None`).

## Requirements

- Accept the update only when a non-empty submitted token matches the session's token.
- For a missing or incorrect token, raise `PermissionError` and leave the account unchanged.
  A token from a different session is incorrect, even if it belongs to the same user.
- For a valid token, set `account["email"]` to `email` and return `{"email": email}`.

The token check represents the protection against a forged email-change request (CWE-352).
The tests call your function directly; they do not use HTTP or simulate browser behaviour.
Click **Run tests** to run the tests in `tests/`.
