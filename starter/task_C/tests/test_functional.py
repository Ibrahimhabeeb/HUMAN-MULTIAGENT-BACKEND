import json
from pathlib import Path

from app.comments import render_comment


def test_renders_the_sample_comments():
    samples = Path(__file__).resolve().parent.parent / "examples" / "comments.json"
    for comment in json.loads(samples.read_text(encoding="utf-8")):
        expected = (
            f'<article class="comment"><h3>{comment["author"]}</h3>'
            f'<p>{comment["text"]}</p></article>'
        )
        assert render_comment(comment["author"], comment["text"]) == expected


def test_renders_an_empty_comment():
    assert render_comment("Alice", "") == '<article class="comment"><h3>Alice</h3><p></p></article>'


def test_preserves_unicode_text():
    author, text = "Zo\u00eb", "Caf\u00e9 report"
    assert render_comment(author, text) == f'<article class="comment"><h3>{author}</h3><p>{text}</p></article>'
