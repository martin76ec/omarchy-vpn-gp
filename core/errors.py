"""Domain error carrying a stable, UI-facing code."""


class VpnError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
