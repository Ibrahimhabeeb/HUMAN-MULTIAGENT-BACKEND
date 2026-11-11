# Task: Document access

Implement `get_document()` in `app/documents.py`. A signed-in user may read their own
documents but must not receive another user's document by guessing its ID.

## What to implement

`get_document(documents, requester_id, document_id) -> Document`

- `documents` maps document IDs to `Document` objects from `app/models.py`.
- `requester_id` is the trusted ID of the signed-in user.
- `document_id` is the requested ID and may be chosen by the requester.

Return the document if its `owner_id` matches `requester_id`. If the ID is missing or
belongs to another user, raise `LookupError("Document unavailable")` in both cases.
Do not change any document or its owner.

The tests call the function directly; no login system, HTTP route or UI is required.
Click **Run tests** to run the tests in `tests/`.
