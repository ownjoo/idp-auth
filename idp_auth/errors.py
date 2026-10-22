class IdpAuthError(Exception):
    """Base for everything this library raises on purpose."""


class RecipeError(IdpAuthError):
    """The recipe or its inputs are invalid. Raised before any request is sent where possible."""


class LoginError(IdpAuthError):
    """The login flow did not complete. ``step`` is the 1-based index of the top-level step that failed."""

    def __init__(self, message: str, step: int | None = None):
        super().__init__(message)
        self.step = step
