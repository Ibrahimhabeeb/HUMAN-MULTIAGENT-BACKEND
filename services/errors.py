class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class StateRuleError(ConflictError):
    pass


class InvalidInputError(ValueError):
    pass


class InvalidPathError(InvalidInputError):
    pass
