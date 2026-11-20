import pytest
from app import storage


@pytest.fixture
def file_area(tmp_path, monkeypatch):
    public = tmp_path / "files"
    public.mkdir()
    (public / "welcome.txt").write_bytes(b"Public document")
    (public / "news..txt").write_bytes(b"Ordinary filename")
    (public / "nested").mkdir()
    for name in ("private", "files_backup"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "secret.txt").write_bytes(b"Private information")
    monkeypatch.setattr(storage, "STORAGE_DIR", public)
    return tmp_path / "private" / "secret.txt"


@pytest.mark.parametrize("filename,expected", [
    ("welcome.txt", b"Public document"), ("news..txt", b"Ordinary filename"),
])
def test_ordinary_filenames_remain_downloadable(file_area, filename, expected):
    assert storage.download(filename) == expected


@pytest.mark.parametrize("filename", [
    "../private/secret.txt", "../files_backup/secret.txt", "nested/../../private/secret.txt",
])
def test_relative_paths_cannot_escape_storage(file_area, filename):
    with pytest.raises((OSError, ValueError)):
        storage.download(filename)


def test_absolute_path_outside_storage_is_refused(file_area):
    with pytest.raises((OSError, ValueError)):
        storage.download(str(file_area))


def test_listing_contains_only_downloadable_public_files(file_area):
    assert set(storage.list_files()) == {"welcome.txt", "news..txt"}


def test_missing_file_is_reported(file_area):
    with pytest.raises(FileNotFoundError):
        storage.download("missing.txt")
