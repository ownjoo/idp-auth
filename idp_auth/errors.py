REASONS = ('rejected', 'transport', 'mfa_required', 'flow')


class IdpAuthError(Exception):
    """Base for everything this library raises on purpose."""


class RecipeError(IdpAuthError):
    """The recipe or its inputs are invalid. Raised before any request is sent where possible."""


class LoginError(IdpAuthError):
    """The login flow did not complete.

    - ``reason``: ``rejected`` (the IdP refused the credentials or code), ``transport`` (a request could not be
      sent or answered), ``mfa_required`` (a factor was asked for that the inputs can't satisfy) or ``flow``
      (anything else: unexpected page, missing field, recipe ``fail``).
    - ``step``: 1-based index of the top-level recipe step that failed.
    - ``url``: the URL involved, without query string or fragment.
    - ``status_code``: status of the last response received, if any.

    The original exception is deliberately not chained: transport errors carry full URLs, query-string tokens
    included, and a chained cause would print them in every traceback.
    """

    def __init__(
        self,
        message: str,
        step: int | None = None,
        reason: str = 'flow',
        url: str | None = None,
        status_code: int | None = None,
    ):
        super().__init__(message)
        self.step = step
        self.reason = reason
        self.url = url
        self.status_code = status_code
