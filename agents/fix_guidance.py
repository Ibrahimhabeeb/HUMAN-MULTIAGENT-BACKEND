FIX_GUIDANCE = """
Every suggested code fix must name its full workspace-relative file path, e.g. app/auth.py, not just auth.py.
Use suggest_fix with a non-empty file path and precise location: name the function or class, the current line(s)
or a unique nearby statement, and whether to replace, insert before/after, or add the code. If a new file is
needed, say to create that file in location. Never leave the developer guessing where a snippet belongs.
In chat, put the file path and location immediately before any fix snippet and use a fenced code block with
the correct language (python for .py). These are suggestions only: the developer writes the application code.
"""
