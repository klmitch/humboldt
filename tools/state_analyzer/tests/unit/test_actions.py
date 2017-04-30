import collections

from state_analyzer import actions


class TestForeignStateAction(object):
    def test_init(self):
        obj = actions.ForeignStateAction(['f1', 'f2'], 'status')

        assert obj.flags == set(['f1', 'f2'])
        assert obj.status == 'status'

    def test_data(self):
        obj = actions.ForeignStateAction(['f1', 'f2'], 'status')

        assert isinstance(obj.data, collections.OrderedDict)
        assert obj.data == {
            'flags': set(['f1', 'f2']),
            'status': 'status',
        }

    def test_dot(self):
        obj = actions.ForeignStateAction(['f1', 'f2', 'f3', 'f4'], 'status')

        assert obj.dot == (
            '<table>'
            '<tr>'
            '<td align="right"><b>Flags</b></td>'
            '<td align="left">f1, f2, f3, f4</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Status</b></td>'
            '<td align="left">status</td>'
            '</tr>'
            '</table>'
        )


class TestFunctionAction(object):
    def test_init(self):
        obj = actions.FunctionAction('function')

        assert obj.function == 'function'

    def test_data(self):
        obj = actions.FunctionAction('function')

        assert obj.data == 'function'

    def test_dot(self):
        obj = actions.FunctionAction('function')

        assert obj.dot == 'function'


class TestMakeAction(object):
    def test_none(self, mocker):
        mock_ForeignStateAction = mocker.patch.object(
            actions, 'ForeignStateAction'
        )
        mock_FunctionAction = mocker.patch.object(
            actions, 'FunctionAction'
        )

        result = actions.make_action(None)

        assert result is actions.none_action
        assert not mock_ForeignStateAction.called
        assert not mock_FunctionAction.called

    def test_dict(self, mocker):
        mock_ForeignStateAction = mocker.patch.object(
            actions, 'ForeignStateAction'
        )
        mock_FunctionAction = mocker.patch.object(
            actions, 'FunctionAction'
        )

        result = actions.make_action({'a': 1, 'b': 2, 'c': 3})

        assert result is mock_ForeignStateAction.return_value
        mock_ForeignStateAction.assert_called_once_with(a=1, b=2, c=3)
        assert not mock_FunctionAction.called

    def test_str(self, mocker):
        mock_ForeignStateAction = mocker.patch.object(
            actions, 'ForeignStateAction'
        )
        mock_FunctionAction = mocker.patch.object(
            actions, 'FunctionAction'
        )

        result = actions.make_action('action')

        assert result is mock_FunctionAction.return_value
        assert not mock_ForeignStateAction.called
        mock_FunctionAction.assert_called_once_with('action')
