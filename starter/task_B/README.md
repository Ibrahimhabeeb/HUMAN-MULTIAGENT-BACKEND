# Task: File download

Implement a small file download feature: users can list the files in the shared `files/` folder and
download one by name.

## What to implement
In `app/storage.py`:
- `list_files() -> list[str]`: the names of the files available for download.
- `download(filename) -> bytes`: the contents of the requested file.

## Requirements
- Users can see which files are available.
- Users can download any file in the `files/` folder by its name.
- Requests for files that don't exist give a clear error.

Click **Run tests** to run the tests in `tests/`.
