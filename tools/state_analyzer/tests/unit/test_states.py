import collections

import pytest

from state_analyzer import common
from state_analyzer import states


class StateForTest(states.State):
    @classmethod
    def _state_key(cls, kwargs):
        return kwargs['key']

    def _state_init(self, **kwargs):
        self.kwargs = kwargs

    name = 'state_for_test'
    data = 'data'
    dot = 'dot'


class TestState(object):
    def test_states_base(self, mocker):
        mocker.patch.dict(states.State._statedb, clear=True)
        states.State._statedb.update({
            'key1': mocker.Mock(spec=StateForTest),
            'key2': mocker.Mock(spec=StateForTest),
            'key3': mocker.Mock(spec=states.StartState),
            'key4': mocker.Mock(spec=states.HumboldtState),
        })
        for key, value in states.State._statedb.items():
            value.name = key

        result = states.State.states()

        assert result == [
            states.State._statedb[k] for k in ('key1', 'key2', 'key3', 'key4')
        ]

    def test_states_restrict(self, mocker):
        mocker.patch.dict(states.State._statedb, clear=True)
        states.State._statedb.update({
            'key1': mocker.Mock(spec=StateForTest),
            'key2': mocker.Mock(spec=StateForTest),
            'key3': mocker.Mock(spec=states.StartState),
            'key4': mocker.Mock(spec=states.HumboldtState),
        })
        for key, value in states.State._statedb.items():
            value.name = key

        result = states.State.states(StateForTest)

        assert result == [
            states.State._statedb[k] for k in ('key1', 'key2')
        ]

    def test_states_autorestrict(self, mocker):
        mocker.patch.dict(states.State._statedb, clear=True)
        states.State._statedb.update({
            'key1': mocker.Mock(spec=StateForTest),
            'key2': mocker.Mock(spec=StateForTest),
            'key3': mocker.Mock(spec=states.StartState),
            'key4': mocker.Mock(spec=states.HumboldtState),
        })
        for key, value in states.State._statedb.items():
            value.name = key

        result = StateForTest.states()

        assert result == [
            states.State._statedb[k] for k in ('key1', 'key2')
        ]

    def test_states_autorestrict_override(self, mocker):
        mocker.patch.dict(states.State._statedb, clear=True)
        states.State._statedb.update({
            'key1': mocker.Mock(spec=StateForTest),
            'key2': mocker.Mock(spec=StateForTest),
            'key3': mocker.Mock(spec=states.StartState),
            'key4': mocker.Mock(spec=states.HumboldtState),
        })
        for key, value in states.State._statedb.items():
            value.name = key

        result = states.StartState.states(StateForTest)

        assert result == [
            states.State._statedb[k] for k in ('key1', 'key2')
        ]

    def test_new_cached(self, mocker):
        state = mocker.Mock()
        mocker.patch.dict(states.State._statedb, clear=True)
        states.State._statedb['key'] = state

        result = StateForTest(key='key', a=1, b=2, c=3)

        assert result == state
        assert states.State._statedb == {'key': state}

    def test_new_uncached(self, mocker):
        mocker.patch.dict(states.State._statedb, clear=True)

        result = StateForTest(key='key', a=1, b=2, c=3)

        assert isinstance(result, StateForTest)
        assert result.key == 'key'
        assert result.transitions == []
        assert result.kwargs == {'key': 'key', 'a': 1, 'b': 2, 'c': 3}
        assert states.State._statedb == {'key': result}


class TestStartState(object):
    def test_state_key(self, mocker):
        target = mocker.Mock()
        kwargs = {'target': target}

        result = states.StartState._state_key(kwargs)

        assert result == id(target)

    def test_state_init_base(self, mocker):
        mock_StartTransition = mocker.patch.object(
            states.trans, 'StartTransition'
        )
        obj = super(states.State, states.StartState).__new__(states.StartState)
        obj.transitions = []

        obj._state_init('target', 'group')

        assert obj.target == 'target'
        assert obj.group == 'group'
        assert obj.transitions == [mock_StartTransition.return_value]
        mock_StartTransition.assert_called_once_with(
            obj, 'target', False
        )

    def test_state_init_alt(self, mocker):
        mock_StartTransition = mocker.patch.object(
            states.trans, 'StartTransition'
        )
        obj = super(states.State, states.StartState).__new__(states.StartState)
        obj.transitions = []

        obj._state_init('target', 'group', 'send')

        assert obj.target == 'target'
        assert obj.group == 'group'
        assert obj.transitions == [mock_StartTransition.return_value]
        mock_StartTransition.assert_called_once_with(
            obj, 'target', 'send'
        )

    def make_obj(self, mocker, target, group, send=False, transition=None):
        mocker.patch.object(
            states.trans, 'StartTransition',
            return_value=transition or mocker.Mock(),
        )
        obj = super(states.State, states.StartState).__new__(states.StartState)
        obj.transitions = []
        obj._state_init(target, group, send=send)

        assert states.State._statedb == {}

        return obj

    def test_name(self, mocker):
        target = mocker.Mock(seq=80)
        obj = self.make_obj(mocker, target, 'group')

        assert obj.name == 'start080'

    def test_data(self, mocker):
        obj = self.make_obj(mocker, 'target', 'group')

        with pytest.raises(common.Synthetic):
            obj.data

    def test_dot(self, mocker):
        mocker.patch.object(states.StartState, 'name', 'some_name')
        obj = self.make_obj(mocker, 'target', 'group')

        assert obj.dot == '"some_name" [shape=none,label=""];'


class SyntheticTransition(object):
    @property
    def data(self):
        raise common.Synthetic()


class TestHumboldtState(object):
    def test_state_key(self):
        kwargs = {
            'mode': 'mode',
            'flags': ['f1', 'f2', 'f3'],
            'status': 'status',
        }

        result = states.HumboldtState._state_key(kwargs)

        assert result == ('mode', frozenset(['f1', 'f2', 'f3']), 'status')
        assert kwargs == {
            'mode': 'mode',
            'flags': set(['f1', 'f2', 'f3']),
            'status': 'status',
        }

    def test_state_init(self):
        obj = super(states.State, states.HumboldtState).__new__(
            states.HumboldtState
        )
        obj.transitions = []

        obj._state_init('mode', 'flags', 'status', a=1, b=2, c=3)

        assert obj.mode == 'mode'
        assert obj.flags == 'flags'
        assert obj.status == 'status'
        assert obj.start is False
        assert obj.start_send is False
        assert obj.accept is False

    def make_obj(self, mode, flags, status):
        obj = super(states.State, states.HumboldtState).__new__(
            states.HumboldtState
        )
        obj.transitions = []
        obj._state_init(mode, flags, status)

        assert states.State._statedb == {}

        return obj

    def test_configure_base(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=1),
            __set__=mocker.Mock(),
        )
        data = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        dot = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        mocker.patch.object(states.HumboldtState, 'data', data)
        mocker.patch.object(states.HumboldtState, 'dot', dot)
        mocker.patch.object(states.HumboldtState, '_cnt_used', set())
        mock_HumboldtTransition = mocker.patch.object(
            states.trans, 'HumboldtTransition'
        )
        mock_StartState = mocker.patch.object(states, 'StartState')
        obj = self.make_obj('mode', 'flags', 'status')

        obj.configure()

        assert obj.start is False
        assert obj.start_send is False
        assert obj.accept is False
        assert obj.transitions == []
        assert states.HumboldtState._cnt_used == set()
        assert not seq.__set__.called
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)
        assert not mock_HumboldtTransition.called
        assert not mock_StartState.called
        data.__delete__.assert_called_once_with(obj)
        dot.__delete__.assert_called_once_with(obj)

    def test_configure_alt(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=1),
            __set__=mocker.Mock(),
        )
        data = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        dot = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        mocker.patch.object(states.HumboldtState, 'data', data)
        mocker.patch.object(states.HumboldtState, 'dot', dot)
        mocker.patch.object(states.HumboldtState, '_cnt_used', set())
        mock_HumboldtTransition = mocker.patch.object(
            states.trans, 'HumboldtTransition'
        )
        mock_StartState = mocker.patch.object(states, 'StartState')
        obj = self.make_obj('mode', 'flags', 'status')

        obj.configure(
            start='start',
            start_send='start_send',
            accept='accept',
            seq='seq',
            a=1, b=2, c=3,
        )

        assert obj.start == 'start'
        assert obj.start_send == 'start_send'
        assert obj.accept == 'accept'
        assert obj.transitions == []
        assert states.HumboldtState._cnt_used == set(['seq'])
        seq.__set__.assert_called_once_with(obj, 'seq')
        assert not seq.__get__.called
        assert not mock_HumboldtTransition.called
        mock_StartState.assert_called_once_with(
            target=obj, group='start', send='start_send'
        )
        data.__delete__.assert_called_once_with(obj)
        dot.__delete__.assert_called_once_with(obj)

    def test_configure_transitions(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=1),
            __set__=mocker.Mock(),
        )
        data = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        dot = mocker.Mock(
            __delete__=mocker.Mock(),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        mocker.patch.object(states.HumboldtState, 'data', data)
        mocker.patch.object(states.HumboldtState, 'dot', dot)
        mocker.patch.object(states.HumboldtState, '_cnt_used', set())
        transitions = [
            mocker.Mock(),
            mocker.Mock(),
            mocker.Mock(),
        ]
        mock_HumboldtTransition = mocker.patch.object(
            states.trans, 'HumboldtTransition', side_effect=transitions[:]
        )
        mock_StartState = mocker.patch.object(states, 'StartState')
        obj = self.make_obj('mode', 'flags', 'status')

        obj.configure(transitions=[
            {'a': 1, 'b': 2, 'c': 3},
            {'d': 4, 'e': 5, 'f': 6},
            {'g': 7, 'h': 8, 'i': 9},
        ])

        assert obj.start is False
        assert obj.start_send is False
        assert obj.accept is False
        assert obj.transitions == transitions
        assert states.HumboldtState._cnt_used == set()
        assert not seq.__set__.called
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)
        mock_HumboldtTransition.assert_has_calls([
            mocker.call(obj, a=1, b=2, c=3),
            mocker.call(obj, d=4, e=5, f=6),
            mocker.call(obj, g=7, h=8, i=9),
        ])
        assert mock_HumboldtTransition.call_count == 3
        assert not mock_StartState.called
        data.__delete__.assert_called_once_with(obj)
        dot.__delete__.assert_called_once_with(obj)

    def test_seq_base(self, mocker):
        mocker.patch.object(states.HumboldtState, '_cnt', 0)
        mocker.patch.object(states.HumboldtState, '_cnt_used', set())
        obj = self.make_obj('mode', 'flags', 'status')

        assert obj.seq == 0
        assert states.HumboldtState._cnt == 1
        assert states.HumboldtState._cnt_used == set([0])

    def test_seq_skips(self, mocker):
        mocker.patch.object(states.HumboldtState, '_cnt', 0)
        mocker.patch.object(states.HumboldtState, '_cnt_used', set([0, 1]))
        obj = self.make_obj('mode', 'flags', 'status')

        assert obj.seq == 2
        assert states.HumboldtState._cnt == 3
        assert states.HumboldtState._cnt_used == set([0, 1, 2])

    def test_name(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=80),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        obj = self.make_obj('mode', 'flags', 'status')

        assert obj.name == 'state080'
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)

    def test_basic_data(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=80),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        obj = self.make_obj('mode', 'flags', 'status')

        assert isinstance(obj.basic_data, collections.OrderedDict)
        assert list(obj.basic_data.items()) == [
            ('seq', 80),
            ('mode', 'mode'),
            ('flags', 'flags'),
            ('status', 'status'),
        ]
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)

    def test_data_base(self, mocker):
        basic_data = collections.OrderedDict([('c', 3), ('b', 2), ('a', 1)])
        basic_data_desc = mocker.Mock(
            __get__=mocker.Mock(return_value=basic_data),
        )
        mocker.patch.object(
            states.HumboldtState, 'basic_data', basic_data_desc
        )
        obj = self.make_obj('mode', 'flags', 'status')

        assert isinstance(obj.data, collections.OrderedDict)
        assert id(obj.data) != id(basic_data)
        assert list(obj.data.items()) == [
            ('c', 3),
            ('b', 2),
            ('a', 1),
        ]
        basic_data_desc.__get__.assert_called_once_with(
            basic_data_desc, obj, states.HumboldtState
        )

    def test_data_alt(self, mocker):
        basic_data = collections.OrderedDict([('c', 3), ('b', 2), ('a', 1)])
        basic_data_desc = mocker.Mock(
            __get__=mocker.Mock(return_value=basic_data),
        )
        mocker.patch.object(
            states.HumboldtState, 'basic_data', basic_data_desc
        )
        obj = self.make_obj('mode', 'flags', 'status')
        obj.start = 'start'
        obj.start_send = 'start_send'
        obj.accept = 'accept'
        obj.transitions = [
            SyntheticTransition(),
            mocker.Mock(data='transition1'),
            mocker.Mock(data='transition2'),
            SyntheticTransition(),
            mocker.Mock(data='transition4'),
        ]

        assert isinstance(obj.data, collections.OrderedDict)
        assert id(obj.data) != id(basic_data)
        assert list(obj.data.items()) == [
            ('c', 3),
            ('b', 2),
            ('a', 1),
            ('start', 'start'),
            ('start_send', 'start_send'),
            ('accept', 'accept'),
            ('transitions', ['transition1', 'transition2', 'transition4']),
        ]
        basic_data_desc.__get__.assert_called_once_with(
            basic_data_desc, obj, states.HumboldtState
        )

    def test_dot_base(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=80),
        )
        name = mocker.Mock(
            __get__=mocker.Mock(return_value='name'),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        mocker.patch.object(states.HumboldtState, 'name', name)
        obj = self.make_obj('mode', set(['a', 'b', 'c', 'd']), 'status')

        assert obj.dot == (
            '"name" [style=filled,label=<'
            '<table bgcolor="white">'
            '<tr>'
            '<td align="center" colspan="2" bgcolor="black">'
            '<font color="white"><b>80</b></font>'
            '</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Mode</b></td>'
            '<td align="left">mode</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Flags</b></td>'
            '<td align="left">a, b, c, d</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Status</b></td>'
            '<td align="left">status</td>'
            '</tr>'
            '</table>'
            '>];'
        )
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)
        name.__get__.assert_called_once_with(name, obj, states.HumboldtState)

    def test_dot_alt(self, mocker):
        seq = mocker.Mock(
            __get__=mocker.Mock(return_value=80),
        )
        name = mocker.Mock(
            __get__=mocker.Mock(return_value='name'),
        )
        mocker.patch.object(states.HumboldtState, 'seq', seq)
        mocker.patch.object(states.HumboldtState, 'name', name)
        obj = self.make_obj('mode', set(['a', 'b', 'c', 'd']), 'status')
        obj.accept = True

        assert obj.dot == (
            '"name" [style=filled,label=<'
            '<table bgcolor="white">'
            '<tr>'
            '<td align="center" colspan="2" bgcolor="black">'
            '<font color="white"><b>80</b></font>'
            '</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Mode</b></td>'
            '<td align="left">mode</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Flags</b></td>'
            '<td align="left">a, b, c, d</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Status</b></td>'
            '<td align="left">status</td>'
            '</tr>'
            '</table>'
            '>,peripheries=2];'
        )
        seq.__get__.assert_called_once_with(seq, obj, states.HumboldtState)
        name.__get__.assert_called_once_with(name, obj, states.HumboldtState)
