import pkg_resources
import pytest

from hum_proto import entrypoints


class TestEntrypointDict(object):
    def test_init(self):
        result = entrypoints.EntrypointDict('group.name')

        assert result._group == 'group.name'
        assert result._entries == {}

    def test_len(self):
        obj = entrypoints.EntrypointDict('group.name')
        obj._entries = {
            'ent1': 'ep1',
            'ent2': 'ep2',
            'ent3': entrypoints._notfound,
            'ent4': 'ep4',
            'ent5': entrypoints._notfound,
        }

        assert len(obj) == 3

    def test_getitem_available(self, mocker):
        mock_missing = mocker.patch.object(
            entrypoints.EntrypointDict, '__missing__'
        )
        obj = entrypoints.EntrypointDict('group.name')
        obj._entries = {
            'ent1': 'ep1',
            'ent2': 'ep2',
            'ent3': entrypoints._notfound,
            'ent4': 'ep4',
            'ent5': entrypoints._notfound,
        }

        result = obj.__getitem__('ent1')

        assert result == 'ep1'
        assert not mock_missing.called

    def test_getitem_notfound(self, mocker):
        mock_missing = mocker.patch.object(
            entrypoints.EntrypointDict, '__missing__'
        )
        obj = entrypoints.EntrypointDict('group.name')
        obj._entries = {
            'ent1': 'ep1',
            'ent2': 'ep2',
            'ent3': entrypoints._notfound,
            'ent4': 'ep4',
            'ent5': entrypoints._notfound,
        }

        with pytest.raises(KeyError):
            obj.__getitem__('ent3')
        assert not mock_missing.called

    def test_getitem_missing(self, mocker):
        mock_missing = mocker.patch.object(
            entrypoints.EntrypointDict, '__missing__'
        )
        obj = entrypoints.EntrypointDict('group.name')
        obj._entries = {
            'ent1': 'ep1',
            'ent2': 'ep2',
            'ent3': entrypoints._notfound,
            'ent4': 'ep4',
            'ent5': entrypoints._notfound,
        }

        result = obj.__getitem__('ent6')

        assert result == mock_missing.return_value
        mock_missing.assert_called_once_with('ent6')

    def test_iter(self, mocker):
        obj = entrypoints.EntrypointDict('group.name')
        obj._entries = {
            'ent1': 'ep1',
            'ent2': 'ep2',
            'ent3': entrypoints._notfound,
            'ent4': 'ep4',
            'ent5': entrypoints._notfound,
        }

        result = set(iter(obj))

        assert result == set(['ent1', 'ent2', 'ent4'])

    def test_missing_found(self, mocker):
        eps = [
            mocker.Mock(**{'load.side_effect': ImportError()}),
            mocker.Mock(**{'load.side_effect': AttributeError()}),
            mocker.Mock(**{'load.side_effect': pkg_resources.UnknownExtra()}),
            mocker.Mock(**{'load.return_value': 'obj1'}),
            mocker.Mock(**{'load.return_value': 'obj2'}),
        ]
        mock_iter_entry_points = mocker.patch.object(
            entrypoints.pkg_resources, 'iter_entry_points', return_value=eps
        )
        obj = entrypoints.EntrypointDict('group.name')

        result = obj.__missing__('endpoint')

        assert result == 'obj1'
        assert obj._entries == {'endpoint': 'obj1'}
        mock_iter_entry_points.assert_called_once_with(
            'group.name', 'endpoint'
        )
        for i, ep in enumerate(eps):
            if i == len(eps) - 1:
                assert not ep.load.called
            else:
                ep.load.assert_called_once_with()

    def test_missing_found_nonstr(self, mocker):
        eps = [
            mocker.Mock(**{'load.side_effect': ImportError()}),
            mocker.Mock(**{'load.side_effect': AttributeError()}),
            mocker.Mock(**{'load.side_effect': pkg_resources.UnknownExtra()}),
            mocker.Mock(**{'load.return_value': 'obj1'}),
            mocker.Mock(**{'load.return_value': 'obj2'}),
        ]
        mock_iter_entry_points = mocker.patch.object(
            entrypoints.pkg_resources, 'iter_entry_points', return_value=eps
        )
        obj = entrypoints.EntrypointDict('group.name')

        result = obj.__missing__(5)

        assert result == 'obj1'
        assert obj._entries == {5: 'obj1'}
        mock_iter_entry_points.assert_called_once_with(
            'group.name', '5'
        )
        for i, ep in enumerate(eps):
            if i == len(eps) - 1:
                assert not ep.load.called
            else:
                ep.load.assert_called_once_with()

    def test_missing_notfound(self, mocker):
        eps = [
            mocker.Mock(**{'load.side_effect': ImportError()}),
            mocker.Mock(**{'load.side_effect': AttributeError()}),
            mocker.Mock(**{'load.side_effect': pkg_resources.UnknownExtra()}),
        ]
        mock_iter_entry_points = mocker.patch.object(
            entrypoints.pkg_resources, 'iter_entry_points', return_value=eps
        )
        obj = entrypoints.EntrypointDict('group.name')

        with pytest.raises(KeyError):
            obj.__missing__('endpoint')
        assert obj._entries == {'endpoint': entrypoints._notfound}
        mock_iter_entry_points.assert_called_once_with(
            'group.name', 'endpoint'
        )
        for i, ep in enumerate(eps):
            ep.load.assert_called_once_with()
