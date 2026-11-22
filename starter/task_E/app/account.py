import secrets  # noqa: F401

from app.models import Account


def update_email(
    account: Account, session: dict[str, str], email: str, request_token: str | None
) -> dict[str, str]:
    # Write your code here. For more clarification, use the chat panel.
    # TODO: reject a missing or incorrect request token before updating the email.
    raise NotImplementedError
