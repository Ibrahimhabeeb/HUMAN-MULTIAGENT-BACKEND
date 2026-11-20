import pytest
from app.account import update_email
from app.models import Account


def test_valid_token_updates_the_account():
    account = Account(email="alice@example.test")
    session = {"request_token": "alice-token"}

    result = update_email(account, session, "new@example.test", "alice-token")

    assert result == {"email": "new@example.test"}
    assert account.email == "new@example.test"


def test_missing_token_is_rejected_without_changing_the_account():
    account = Account(email="alice@example.test")
    session = {"request_token": "alice-token"}

    with pytest.raises(PermissionError):
        update_email(account, session, "new@example.test", None)

    assert account.email == "alice@example.test"
