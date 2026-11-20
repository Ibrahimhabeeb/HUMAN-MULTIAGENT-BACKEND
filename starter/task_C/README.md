# Task: Comment rendering

Implement the server-side HTML renderer for a small comment feature.
No browser interface or web server needs to be built.

## What to implement
In `app/comments.py`:
- `render_comment(author: str, text: str) -> str`

Return one comment using this HTML structure:

```html
<article class="comment"><h3>AUTHOR</h3><p>TEXT</p></article>
```

Replace AUTHOR and TEXT with the supplied strings.

## Requirements
- Display the author's name in the heading and their comment in the paragraph.
- Preserve ordinary punctuation, Unicode text and empty comments.
- Both strings come from users and must be displayed as text, not treated as HTML.
- Keep the surrounding article, heading and paragraph markup.

`examples/comments.json` contains sample input.
Click **Run tests** to run the tests in `tests/`.
