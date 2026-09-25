import unittest

from core.errors import VpnError
from core.fsm import ConnectionFSM, State


class FsmTests(unittest.TestCase):
    def test_illegal_transitions_raise(self):
        for state, target in [
            (State.DISCONNECTED, State.DISCONNECTING),
            (State.DISCONNECTED, State.CONNECTED),
            (State.CONNECTED, State.CONNECTING),
            (State.DISCONNECTING, State.CONNECTING),
            # A second connect/verify must not be startable mid-prompt.
            (State.AUTHENTICATING, State.CONNECTING),
        ]:
            with self.subTest(f"{state}->{target}"), self.assertRaises(VpnError) as ctx:
                ConnectionFSM(state).transition(target)
            self.assertEqual(ctx.exception.code, "INVALID_STATE")

    def test_happy_path(self):
        fsm = ConnectionFSM()
        for target in (State.CONNECTING, State.AUTHENTICATING, State.CONNECTED, State.DISCONNECTING, State.DISCONNECTED):
            self.assertEqual(fsm.transition(target), target)

    def test_error_is_recoverable(self):
        self.assertEqual(ConnectionFSM(State.ERROR).transition(State.CONNECTING), State.CONNECTING)
