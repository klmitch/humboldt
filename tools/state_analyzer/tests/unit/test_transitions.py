import collections

import pytest

from state_analyzer import common
from state_analyzer import states
from state_analyzer import transitions


class TestStartTransition(object):
    def test_init_base(self):
        result = transitions.StartTransition('origin', 'target')

        assert result.origin == 'origin'
        assert result.target == 'target'
        assert result.send is False

    def test_init_alt(self):
        result = transitions.StartTransition('origin', 'target', 'send')

        assert result.origin == 'origin'
        assert result.target == 'target'
        assert result.send == 'send'

    def test_data(self):
        obj = transitions.StartTransition('origin', 'target')

        with pytest.raises(common.Synthetic):
            obj.data

    def test_dot_base(self, mocker):
        origin = mocker.Mock()
        origin.name = 'origin'
        target = mocker.Mock()
        target.name = 'target'
        obj = transitions.StartTransition(origin, target)

        assert obj.dot == '"origin" -> "target" [color=blue];'

    def test_dot_alt(self, mocker):
        origin = mocker.Mock()
        origin.name = 'origin'
        target = mocker.Mock()
        target.name = 'target'
        obj = transitions.StartTransition(origin, target, True)

        assert obj.dot == '"origin" -> "target" [color=red];'


class TestHumboldtTransition(object):
    def test_init_base(self, mocker):
        mock_HumboldtState = mocker.patch.object(states, 'HumboldtState')
        mock_make_action = mocker.patch.object(
            transitions.actions, 'make_action', side_effect=['call1', 'call2'],
        )
        result = transitions.HumboldtTransition('origin')

        assert result.origin == 'origin'
        assert result.target == mock_HumboldtState.return_value
        assert result.expect == 'call1'
        assert result.action == 'call2'
        assert result.send is False
        assert result.expected is True
        mock_HumboldtState.assert_called_once_with()
        mock_make_action.assert_has_calls([
            mocker.call(None),
            mocker.call(None),
        ])

    def test_init_alt(self, mocker):
        mock_HumboldtState = mocker.patch.object(states, 'HumboldtState')
        mock_make_action = mocker.patch.object(
            transitions.actions, 'make_action', side_effect=['call1', 'call2'],
        )
        result = transitions.HumboldtTransition(
            'origin',
            expect='expect',
            action='action',
            send='send',
            expected='expected',
            a=1, b=2, c=3,
        )

        assert result.origin == 'origin'
        assert result.target == mock_HumboldtState.return_value
        assert result.expect == 'call1'
        assert result.action == 'call2'
        assert result.send == 'send'
        assert result.expected == 'expected'
        mock_HumboldtState.assert_called_once_with(a=1, b=2, c=3)
        mock_make_action.assert_has_calls([
            mocker.call('expect'),
            mocker.call('action'),
        ])

    def test_data_base(self, mocker):
        target = mocker.Mock(
            basic_data=collections.OrderedDict([
                ('c', set(['3', '4'])), ('b', '2'), ('a', 1),
            ]),
        )
        expect = mocker.Mock(data='expect_data')
        action = mocker.Mock(data='action_data')
        mocker.patch.object(states, 'HumboldtState', return_value=target)
        mocker.patch.object(
            transitions.actions, 'make_action', side_effect=[expect, action],
        )
        obj = transitions.HumboldtTransition('origin')

        assert isinstance(obj.data, collections.OrderedDict)
        assert id(obj.data) != id(target.basic_data)
        assert list(obj.data.items()) == [
            ('c', set(['3', '4'])),
            ('b', '2'),
            ('a', 1),
            ('expect', 'expect_data'),
            ('action', 'action_data'),
        ]
        assert id(obj.data['c']) != id(target.basic_data['c'])

    def test_data_alt(self, mocker):
        target = mocker.Mock(
            basic_data=collections.OrderedDict([
                ('c', set(['3', '4'])), ('b', '2'), ('a', 1),
            ]),
        )
        expect = mocker.Mock(data='expect_data')
        action = mocker.Mock(data='action_data')
        mocker.patch.object(states, 'HumboldtState', return_value=target)
        mocker.patch.object(
            transitions.actions, 'make_action', side_effect=[expect, action],
        )
        obj = transitions.HumboldtTransition(
            'origin', send=True, expected=False,
        )

        assert isinstance(obj.data, collections.OrderedDict)
        assert id(obj.data) != id(target.basic_data)
        assert list(obj.data.items()) == [
            ('c', set(['3', '4'])),
            ('b', '2'),
            ('a', 1),
            ('expect', 'expect_data'),
            ('action', 'action_data'),
            ('send', True),
            ('expected', False),
        ]
        assert id(obj.data['c']) != id(target.basic_data['c'])

    def test_dot_base(self, mocker):
        origin = mocker.Mock()
        origin.name = 'origin'
        target = mocker.Mock()
        target.name = 'target'
        expect = mocker.Mock(dot='expect_dot')
        action = mocker.Mock(dot='action_dot')
        mocker.patch.object(states, 'HumboldtState', return_value=target)
        mocker.patch.object(
            transitions.actions, 'make_action', side_effect=[expect, action]
        )
        obj = transitions.HumboldtTransition(origin)

        assert obj.dot == (
            '"origin" -> "target" [label=<'
            '<table>'
            '<tr>'
            '<td align="right"><b>Expected</b></td>'
            '<td align="left">expect_dot</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Action</b></td>'
            '<td align="left">action_dot</td>'
            '</tr>'
            '</table>'
            '>,color=blue,style=solid];'
        )

    def test_dot_alt(self, mocker):
        origin = mocker.Mock()
        origin.name = 'origin'
        target = mocker.Mock()
        target.name = 'target'
        expect = mocker.Mock(dot='expect_dot')
        action = mocker.Mock(dot='action_dot')
        mocker.patch.object(states, 'HumboldtState', return_value=target)
        mocker.patch.object(
            transitions.actions, 'make_action', side_effect=[expect, action]
        )
        obj = transitions.HumboldtTransition(
            origin, send=True, expected=False,
        )

        assert obj.dot == (
            '"origin" -> "target" [label=<'
            '<table>'
            '<tr>'
            '<td align="right"><b>Expected</b></td>'
            '<td align="left">expect_dot</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Action</b></td>'
            '<td align="left">action_dot</td>'
            '</tr>'
            '</table>'
            '>,color=red,style=dashed];'
        )
