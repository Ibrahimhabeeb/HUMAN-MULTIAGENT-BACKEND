from html.parser import HTMLParser

import pytest
from app.comments import render_comment


class CommentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events = []

    def handle_starttag(self, tag, attrs):
        self.events.append(("start", tag, attrs))

    def handle_endtag(self, tag):
        self.events.append(("end", tag))

    def handle_data(self, data):
        self.events.append(("text", data))


@pytest.mark.parametrize("field", ["author", "text"])
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(1)"></svg>',
    "</p></article><script>alert(1)</script>",
    '5 < 6 & "quoted" -- Caf\u00e9',
    "&lt;script&gt;alert(1)&lt;/script&gt;",
])
def test_user_input_remains_text(field, payload):
    author = payload if field == "author" else "Alice"
    text = payload if field == "text" else "Hello"
    parser = CommentParser()
    parser.feed(render_comment(author, text))
    parser.close()
    assert parser.events == [
        ("start", "article", [("class", "comment")]),
        ("start", "h3", []), ("text", author), ("end", "h3"),
        ("start", "p", []), ("text", text), ("end", "p"),
        ("end", "article"),
    ]
