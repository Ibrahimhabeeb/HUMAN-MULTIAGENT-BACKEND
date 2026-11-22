"""Recognise a narrow finding that contradicts visible database and test contracts."""

import ast
import re


def _tree(source):
    try:
        return ast.parse(source)
    except SyntaxError:
        return ast.Module(body=[], type_ignores=[])


def _executed_sql(node):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return node.args[0].value
    return None


def expected_duplicate_error(files: dict[str, str], proposal: dict) -> str | None:
    description = proposal.get("description", "")
    if not (re.search(r"\bIntegrityError\b", description, re.IGNORECASE)
            and re.search(r"duplicat|uniqueness|unique constraint", description, re.IGNORECASE)
            and re.search(r"uncaught|unhandled|not (?:caught|handled|converted)|without handling|fails? to (?:catch|handle)", description, re.IGNORECASE)):
        return None
    # A concrete injection finding must still be reviewed even when uniqueness is enforced.
    if proposal.get("cwe") == "CWE-89" or re.search(r"SQL\s+injection", description, re.IGNORECASE):
        return None
    source = files.get(proposal.get("file"), "")
    functions = [node for node in _tree(source).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    target = next((node for node in functions if re.search(rf"\b{re.escape(node.name)}\b", description)
                   or node.lineno <= (proposal.get("line") or 0) <= node.end_lineno), None)
    if target is None:
        return None
    tables = set()
    for node in ast.walk(target):
        if sql := _executed_sql(node):
            match = re.search(r"\bINSERT\s+INTO\s+(\w+)\s*\([^)]*\busername\b", sql, re.IGNORECASE)
            if match:
                tables.add(match[1])
    if not tables:
        return None
    unique = False
    allowed = False
    for path, content in files.items():
        if not path.endswith(".py"):
            continue
        tree = _tree(content)
        for node in ast.walk(tree):
            if (sql := _executed_sql(node)) and any(re.search(
                rf"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(table)}\b", sql, re.IGNORECASE,
            ) for table in tables):
                unique |= bool(re.search(r"\busername\b[^,)]*\bUNIQUE\b|\bUNIQUE\s*\(\s*username\s*\)", sql, re.IGNORECASE))
            if path.startswith("tests/") and isinstance(node, ast.With):
                permits_error = any(
                    isinstance(item.context_expr, ast.Call)
                    and isinstance(item.context_expr.func, ast.Attribute) and item.context_expr.func.attr == "raises"
                    and any(isinstance(part, (ast.Name, ast.Attribute))
                            and (part.id if isinstance(part, ast.Name) else part.attr) == "IntegrityError"
                            for argument in item.context_expr.args for part in ast.walk(argument))
                    for item in node.items
                )
                calls_target = any(isinstance(part, ast.Call) and isinstance(part.func, ast.Name)
                                   and part.func.id == target.name for statement in node.body for part in ast.walk(statement))
                allowed |= permits_error and calls_target
    if not (unique and allowed):
        return None
    return (
        f"The database already rejects duplicate usernames using UNIQUE, and a provided test explicitly accepts "
        f"IntegrityError from {target.name}. Converting that expected exception to ValueError is optional error "
        "handling, not evidence of an authorisation bypass or information leak. Identify a concrete exploitable "
        "path in the supplied code before treating this behaviour as a security vulnerability."
    )
