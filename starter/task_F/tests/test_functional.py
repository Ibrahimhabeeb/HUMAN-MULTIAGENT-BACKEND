import pytest

from app.documents import get_document
from app.models import Document


def test_owner_can_read_their_document():
    own = Document(id=1, owner_id=10, title="Notes", body="Private notes")
    other = Document(id=2, owner_id=20, title="Plan", body="Another user's plan")

    assert get_document({1: own, 2: other}, requester_id=10, document_id=1) is own


def test_another_users_document_is_unavailable():
    other = Document(id=2, owner_id=20, title="Plan", body="Another user's plan")

    with pytest.raises(LookupError, match="Document unavailable"):
        get_document({2: other}, requester_id=10, document_id=2)


def test_unknown_document_is_unavailable():
    with pytest.raises(LookupError, match="Document unavailable"):
        get_document({}, requester_id=10, document_id=99)
