from fastapi import Request


def update_email(request: Request, email: str, csrf_token: str | None) -> dict[str, str]:
    # Write your code here.
    # TODO: process the signed-in account's email update and return {"email": email}.
    raise NotImplementedError
