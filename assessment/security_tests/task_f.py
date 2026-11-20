import pytest
from app.documents import get_document
from app.models import Document


@pytest.fixture
def documents():
    return {
        101: Document(id=101, owner_id=10, title="Alice", body="Alice's private document"),
        202: Document(id=202, owner_id=20, title="Bob", body="Bob's private document"),
    }


@pytest.mark.parametrize("requester_id,document_id", [(10, 202), (20, 101), (999, 101), (0, 101), (-1, 101)])
def test_other_owners_cannot_access_documents(documents, requester_id, document_id):
    before = documents.copy()
    with pytest.raises(LookupError, match="^Document unavailable$"):
        get_document(documents, requester_id, document_id)
    assert documents == before


@pytest.mark.parametrize("document_id", [0, 999, -1])
def test_missing_documents_use_the_same_error(documents, document_id):
    with pytest.raises(LookupError, match="^Document unavailable$"):
        get_document(documents, requester_id=10, document_id=document_id)


@pytest.mark.parametrize("requester_id,document_id", [(10, 101), (20, 202)])
def test_owners_can_access_their_own_documents_without_mutation(documents, requester_id, document_id):
    before = documents.copy()
    assert get_document(documents, requester_id, document_id) is before[document_id]
    assert documents == before
