class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class StateRuleError(ConflictError):
    pass


class InvalidPathError(ValueError):
    pass
