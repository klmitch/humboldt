import collections

from six.moves import builtins

from state_analyzer import common
from state_analyzer import yaml_util


class TestSetRepresenter(object):
    def test_base(self, mocker):
        dumper = mocker.Mock()

        result = yaml_util._set_representer(dumper, set(['a', 'b', 'c', 'd']))

        assert result == dumper.represent_sequence.return_value
        dumper.represent_sequence.assert_called_once_with(
            u'tag:yaml.org,2002:seq',
            ['a', 'b', 'c', 'd'],
            flow_style=True,
        )


class TestOrderedDictRepresenter(object):
    def test_base(self, mocker):
        dumper = mocker.Mock(**{
            'represent_data.side_effect': lambda x: 'repr-%s' % x,
        })
        mock_MappingNode = mocker.patch.object(yaml_util.yaml, 'MappingNode')
        value = collections.OrderedDict([('c', 3), ('b', 2), ('a', 1)])

        result = yaml_util._ordereddict_representer(dumper, value)

        assert result == mock_MappingNode.return_value
        mock_MappingNode.assert_called_once_with(
            u'tag:yaml.org,2002:map',
            [('repr-c', 'repr-3'), ('repr-b', 'repr-2'), ('repr-a', 'repr-1')],
        )
        dumper.represent_data.assert_has_calls([
            mocker.call('c'), mocker.call(3),
            mocker.call('b'), mocker.call(2),
            mocker.call('a'), mocker.call(1),
        ])
        assert dumper.represent_data.call_count == 6


class TestFromFile(object):
    def test_base(self, mocker):
        state_list = [
            mocker.Mock(),
            mocker.Mock(),
            mocker.Mock(),
        ]
        mock_HumboldtState = mocker.patch.object(
            yaml_util.states, 'HumboldtState', side_effect=state_list[:],
        )
        mock_states = mocker.patch.object(
            yaml_util.states.State, 'states'
        )
        handle = mocker.MagicMock()
        handle.__enter__.return_value = handle
        mock_open = mocker.patch.object(builtins, 'open', return_value=handle)
        mock_safe_load = mocker.patch.object(
            yaml_util.yaml, 'safe_load', return_value=[
                {'state': 0},
                {'state': 1},
                {'state': 2},
            ],
        )

        result = yaml_util.from_file('some_file')

        assert result == mock_states.return_value
        mock_open.assert_called_once_with('some_file')
        mock_safe_load.assert_called_once_with(handle)
        mock_HumboldtState.assert_has_calls([
            mocker.call(state=0),
            mocker.call(state=1),
            mocker.call(state=2),
        ])
        assert mock_HumboldtState.call_count == 3
        for i, state in enumerate(state_list):
            state.configure.assert_called_once_with(state=i)
        mock_states.assert_called_once_with()


class SyntheticState(object):
    @property
    def data(self):
        raise common.Synthetic()


class TestToFile(object):
    def test_base(self, mocker):
        handle = mocker.MagicMock()
        handle.__enter__.return_value = handle
        mock_open = mocker.patch.object(builtins, 'open', return_value=handle)
        mock_dump = mocker.patch.object(yaml_util.yaml, 'dump')
        states = [
            SyntheticState(),
            mocker.Mock(data='state1'),
            mocker.Mock(data='state2'),
            SyntheticState(),
            mocker.Mock(data='state4'),
        ]

        yaml_util.to_file('some_file', states)

        mock_open.assert_called_once_with('some_file', 'w')
        mock_dump.assert_called_once_with(
            ['state1', 'state2', 'state4'],
            handle,
            yaml_util.StateAnalyzerDumper,
            default_flow_style=False,
        )
