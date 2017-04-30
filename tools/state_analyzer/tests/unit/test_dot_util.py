import six
from six.moves import builtins

from state_analyzer import dot_util


class TestToFile(object):
    def test_base(self, mocker):
        stream = six.StringIO()
        handle = mocker.MagicMock()
        handle.__enter__.return_value = stream
        mock_open = mocker.patch.object(builtins, 'open', return_value=handle)
        states = [
            mocker.Mock(
                dot='state0',
                transitions=[
                    mocker.Mock(dot='state0->0'),
                    mocker.Mock(dot='state0->1'),
                    mocker.Mock(dot='state0->2'),
                ],
            ),
            mocker.Mock(
                dot='state1',
                transitions=[],
            ),
            mocker.Mock(
                dot='state2',
                transitions=[
                    mocker.Mock(dot='state2->0'),
                    mocker.Mock(dot='state2->1'),
                ],
            ),
        ]

        dot_util.to_file('some_file', states)

        mock_open.assert_called_once_with('some_file', 'w')
        assert stream.getvalue() == (
            'digraph "states" {\n'
            '\trankdir=LR;\n'
            '\n'
            '\tstate0\n'
            '\tstate1\n'
            '\tstate2\n'
            '\n'
            '\tstate0->0\n'
            '\tstate0->1\n'
            '\tstate0->2\n'
            '\tstate2->0\n'
            '\tstate2->1\n'
            '}\n'
        )
