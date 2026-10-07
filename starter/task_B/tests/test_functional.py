import pytest

from app.storage import download, list_files


def test_lists_the_available_files():
    assert sorted(list_files()) == ["report.txt", "welcome.txt"]


def test_downloads_a_file_by_name():
    assert download("welcome.txt").strip() == b"Welcome to the shared file area."


def test_missing_file_gives_an_error():
    with pytest.raises(FileNotFoundError):
        download("missing.txt")
