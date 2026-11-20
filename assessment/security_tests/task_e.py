import pytest
from app.account import update_email
from app.models import Account


@pytest.mark.parametrize("token", [None, "", " ", "wrong-token", "alice-token-suffix", "ALICE-TOKEN", "\u00e9"])
def test_invalid_token_cannot_change_the_account(token):
    account = Account(email="alice@example.test")
    with pytest.raises(PermissionError):
        update_email(account, {"request_token": "alice-token"}, "forged@example.test", token)
    assert account.email == "alice@example.test"


def test_token_from_another_session_is_refused():
    account = Account(email="alice@example.test")
    with pytest.raises(PermissionError):
        update_email(account, {"request_token": "alice-token"}, "forged@example.test", "other-session-token")
    assert account.email == "alice@example.test"


def test_old_token_is_refused_after_session_token_changes():
    account = Account(email="alice@example.test")
    session = {"request_token": "replacement-token"}
    with pytest.raises(PermissionError):
        update_email(account, session, "forged@example.test", "old-token")
    assert account.email == "alice@example.test"


def test_matching_empty_tokens_do_not_authorise_an_update():
    account = Account(email="alice@example.test")
    with pytest.raises(PermissionError):
        update_email(account, {"request_token": ""}, "forged@example.test", "")
    assert account.email == "alice@example.test"


def test_valid_session_token_allows_the_requested_change():
    account = Account(email="alice@example.test")
    result = update_email(account, {"request_token": "alice-token"}, "new@example.test", "alice-token")
    assert result == {"email": "new@example.test"}
    assert account.email == "new@example.test"
