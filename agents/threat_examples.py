"""Extract the Threat Modeller's one illustrative unsafe snippet for the chat UI."""

import ast
import re

_EXAMPLE = re.compile(
    r"<risk-example\s+path=[\"'](?P<path>[^\"']+)[\"']\s*>\s*"
    r"```(?P<language>[\w+-]*)\s*\n(?P<code>.*?)```\s*</risk-example>",
    re.DOTALL,
)


def extract(reply: str, allowed_paths: set[str]) -> tuple[str, dict[str, str] | None]:
    """Return the display reply and a safe, workspace-scoped code-card payload."""
    match = _EXAMPLE.search(reply)
    if match is None:
        return reply, None

    cleaned = (reply[:match.start()] + reply[match.end():]).strip()
    path = match.group("path").strip()
    code = match.group("code").strip()
    if path not in allowed_paths or not code:
        return cleaned, None
    language = match.group("language").strip() or "python"
    example = {"path": path, "code": code, "language": language}
    if language in {"python", "py"}:
        try:
            functions = [node for node in ast.parse(code).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if len(functions) == 1:
                example["function"] = functions[0].name
        except SyntaxError:
            pass  # Partial snippets still render, without claiming to show an entire function.
    return cleaned, example
