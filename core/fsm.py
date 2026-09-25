"""Connection lifecycle states and the transitions the helper permits."""

from enum import StrEnum

from core.errors import VpnError


class State(StrEnum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    AUTHENTICATING = "AUTHENTICATING"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    ERROR = "ERROR"


_S = State
_TRANSITIONS: dict[State, frozenset[State]] = {
    _S.DISCONNECTED: frozenset({_S.CONNECTING}),
    _S.CONNECTING: frozenset({_S.AUTHENTICATING, _S.CONNECTED, _S.DISCONNECTING, _S.DISCONNECTED, _S.ERROR}),
    # No CONNECTING here: a second connect/verify attempt must not be
    # startable while credentials are literally being typed for the first
    # one — found by a test that expected exactly this rejection and
    # didn't get it (AUTHENTICATING -> CONNECTING was legal by oversight,
    # never intentionally, and nothing else depended on it).
    _S.AUTHENTICATING: frozenset({_S.CONNECTED, _S.DISCONNECTING, _S.DISCONNECTED, _S.ERROR}),
    _S.CONNECTED: frozenset({_S.DISCONNECTING, _S.DISCONNECTED, _S.ERROR}),
    _S.DISCONNECTING: frozenset({_S.DISCONNECTED, _S.ERROR}),
    _S.ERROR: frozenset({_S.CONNECTING, _S.DISCONNECTED}),
}


class ConnectionFSM:
    """Seeded from NetworkManager's observed state on every helper run.

    The helper is a short-lived process, so the FSM does not own the truth; it
    only rejects requests that make no sense from the observed state.
    """

    def __init__(self, state: State = State.DISCONNECTED):
        self.state = state

    def transition(self, target: State, reason: str | None = None) -> State:
        if target not in _TRANSITIONS[self.state]:
            raise VpnError("INVALID_STATE", reason or f"Cannot go from {self.state} to {target}.")
        self.state = target
        return target
