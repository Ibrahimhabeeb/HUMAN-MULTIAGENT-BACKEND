from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parent.parent / "files"


def list_files():
    # TODO: return the names of the files in STORAGE_DIR
    raise NotImplementedError


def download(filename):
    # TODO: return the contents of the requested file as bytes
    raise NotImplementedError
