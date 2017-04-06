import pytest

from hum_proto import enum


class TestEnum(object):
    def test_init_base(self):
        result = enum.Enum('foo', 23)

        assert result.name == 'foo'
        assert result.value == 23
        assert result.makehex is False
        assert result.eset is None

    def test_init_hex(self):
        result = enum.Enum('foo', 23, True)

        assert result.name == 'foo'
        assert result.value == 23
        assert result.makehex is True
        assert result.eset is None

    def test_repr_base(self):
        obj = enum.Enum('foo', 23)

        assert repr(obj) == '<Enum "foo" (23)>'

    def test_repr_hex(self):
        obj = enum.Enum('foo', 0x23, True)

        assert repr(obj) == '<Enum "foo" (0x23)>'

    def test_str(self):
        obj = enum.Enum('foo', 23)

        assert str(obj) == 'foo'

    def test_int(self):
        obj = enum.Enum('foo', 23)

        assert int(obj) == 23

    def test_eq_enum(self):
        obj1 = enum.Enum('foo', 23)
        obj2 = enum.Enum('foo', 23)
        obj3 = enum.Enum('foo', 24)
        obj4 = enum.Enum('bar', 23)

        assert obj1 == obj2
        assert not (obj1 == obj3)
        assert not (obj1 == obj4)

    def test_eq_int(self):
        obj = enum.Enum('foo', 23)

        assert obj == 23
        assert not (obj == 24)

    def test_eq_str(self):
        obj = enum.Enum('foo', 23)

        assert obj == 'foo'
        assert not (obj == 'bar')

    def test_eq_other(self):
        obj = enum.Enum('foo', 23)

        assert not (obj == object())

    def test_ne_enum(self):
        obj1 = enum.Enum('foo', 23)
        obj2 = enum.Enum('foo', 23)
        obj3 = enum.Enum('foo', 24)
        obj4 = enum.Enum('bar', 23)

        assert not (obj1 != obj2)
        assert obj1 != obj3
        assert obj1 != obj4

    def test_ne_int(self):
        obj = enum.Enum('foo', 23)

        assert not (obj != 23)
        assert obj != 24

    def test_ne_str(self):
        obj = enum.Enum('foo', 23)

        assert not (obj != 'foo')
        assert obj != 'bar'

    def test_ne_other(self):
        obj = enum.Enum('foo', 23)

        assert obj != object()

    def test_lt_enum(self):
        obj1 = enum.Enum('foo', 23)
        obj2 = enum.Enum('foo', 23)
        obj3 = enum.Enum('qux', 22)
        obj4 = enum.Enum('bar', 24)

        assert not (obj1 < obj2)
        assert not (obj1 < obj3)
        assert obj1 < obj4

    def test_lt_int(self):
        obj = enum.Enum('foo', 23)

        assert not (obj < 23)
        assert not (obj < 22)
        assert obj < 24

    def test_lt_str(self, mocker):
        obj = enum.Enum('foo', 23)
        obj.eset = mocker.Mock(by_name={
            'foo': enum.Enum('foo', 23),
            'qux': enum.Enum('qux', 22),
            'bar': enum.Enum('bar', 24),
        })

        assert not (obj < 'foo')
        assert not (obj < 'qux')
        assert obj < 'bar'

    def test_lt_str_unknown(self, mocker):
        obj = enum.Enum('foo', 23)
        obj.eset = mocker.Mock(by_name={})

        result = obj.__lt__('bar')

        assert result is NotImplemented

    def test_lt_other(self):
        obj = enum.Enum('foo', 23)

        result = obj.__lt__(object())

        assert result is NotImplemented


class TestEnumSet(object):
    def test_init(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname

        result = enum.EnumSet(*opts)

        assert result.opts == tuple(opts)
        assert result.by_name == {obj.xname: obj for obj in opts}
        assert result.by_value == {obj.value: obj for obj in opts}
        for obj in opts:
            assert obj.eset is result

    def test_len(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert len(obj) == len(opts)

    def test_iter(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert list(obj) == opts

    def test_contains_str(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert 'obj1' in obj
        assert 'obj2' in obj
        assert 'obj3' in obj
        assert 'obj4' not in obj

    def test_contains_int(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert 1 in obj
        assert 2 in obj
        assert 3 in obj
        assert 4 not in obj

    def test_contains_other(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert object() not in obj

    def test_getitem_str(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert obj['obj1'] == opts[0]
        assert obj['obj2'] == opts[1]
        assert obj['obj3'] == opts[2]
        with pytest.raises(KeyError):
            obj['obj4']

    def test_getitem_int(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        assert obj[1] == opts[0]
        assert obj[2] == opts[1]
        assert obj[3] == opts[2]
        with pytest.raises(KeyError):
            obj[4]

    def test_getitem_other(self, mocker):
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        with pytest.raises(KeyError):
            obj[object()]

    def test_flagset_base(self, mocker):
        mock_FlagSet = mocker.patch.object(enum, 'FlagSet')
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        result = obj.flagset()

        assert result == mock_FlagSet.return_value
        mock_FlagSet.assert_called_once_with(obj, None)

    def test_flagset_flags(self, mocker):
        mock_FlagSet = mocker.patch.object(enum, 'FlagSet')
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        result = obj.flagset('flags')

        assert result == mock_FlagSet.return_value
        mock_FlagSet.assert_called_once_with(obj, 'flags')

    def test_attr(self, mocker):
        mock_EnumAttr = mocker.patch.object(enum, 'EnumAttr')
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        result = obj.attr

        assert result == mock_EnumAttr.return_value
        mock_EnumAttr.assert_called_once_with(obj)

    def test_flags(self, mocker):
        mock_FlagSetAttr = mocker.patch.object(enum, 'FlagSetAttr')
        opts = [
            mocker.Mock(xname='obj1', value=1, eset=None),
            mocker.Mock(xname='obj2', value=2, eset=None),
            mocker.Mock(xname='obj3', value=3, eset=None),
        ]
        for opt in opts:
            opt.name = opt.xname
        obj = enum.EnumSet(*opts)

        result = obj.flags

        assert result == mock_FlagSetAttr.return_value
        mock_FlagSetAttr.assert_called_once_with(obj)


class TestFlagSet(object):
    def test_init_base(self):
        result = enum.FlagSet('eset')

        assert result.eset == 'eset'
        assert result.bitflags == 0
        assert result.flags == set()
        assert result._notify is None

    def test_init_int_found(self):
        result = enum.FlagSet([1, 2, 4, 8], 7)

        assert result.eset == [1, 2, 4, 8]
        assert result.bitflags == 7
        assert result.flags == set(['1', '2', '4'])
        assert result._notify is None

    def test_init_int_missing(self):
        with pytest.raises(TypeError):
            enum.FlagSet([1, 4, 8], 7)

    def test_init_str_found(self):
        result = enum.FlagSet({'a': 1, 'b': 2, 'c': 4}, 'b')

        assert result.eset == {'a': 1, 'b': 2, 'c': 4}
        assert result.bitflags == 2
        assert result.flags == set(['2'])
        assert result._notify is None

    def test_init_str_missing(self):
        with pytest.raises(TypeError):
            enum.FlagSet({'a': 1, 'c': 4}, 'b')

    def test_init_list_found(self):
        result = enum.FlagSet({'a': 1, 'b': 2, 'c': 4}, ['a', 'c'])

        assert result.eset == {'a': 1, 'b': 2, 'c': 4}
        assert result.bitflags == 5
        assert result.flags == set(['1', '4'])
        assert result._notify is None

    def test_init_list_missing(self):
        with pytest.raises(TypeError):
            enum.FlagSet({'a': 1, 'b': 2, 'c': 4}, ['a', 'c', 'd'])

    def test_repr(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        result = repr(obj)

        assert result == '<FlagSet [1, 2, 8] (0xb)>'

    def test_int(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        result = int(obj)

        assert result == 11

    def test_contains_int_all(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        assert 11 in obj

    def test_contains_int_missing(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        assert 6 not in obj

    def test_contains_str_present(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        assert '2' in obj

    def test_contains_str_absent(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        assert '4' not in obj

    def test_contains_list_all(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])

        assert ['a', 'b'] in obj

    def test_contains_list_missing(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])

        assert ['a', 'c'] not in obj

    def test_contains_list_unknown_flag(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])

        assert ['a', 'e'] not in obj

    def test_iter(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        result = list(iter(obj))

        assert result == [1, 2, 8]

    def test_len(self):
        obj = enum.FlagSet([1, 2, 4, 8], 11)

        assert len(obj) == 3

    def test_add_base(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b'])

        obj.add('d')

        assert obj.bitflags == 11
        assert obj.flags == set(['1', '2', '8'])

    def test_add_unknown_flag(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b'])

        with pytest.raises(TypeError):
            obj.add('e')

        assert obj.bitflags == 3
        assert obj.flags == set(['1', '2'])

    def test_add_notify_changed(self, mocker):
        notifier = mocker.Mock()
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b'])
        obj._notify = notifier

        obj.add('d')

        assert obj.bitflags == 11
        assert obj.flags == set(['1', '2', '8'])
        notifier.assert_called_once_with()

    def test_add_notify_unchanged(self, mocker):
        notifier = mocker.Mock()
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b'])
        obj._notify = notifier

        obj.add('b')

        assert obj.bitflags == 3
        assert obj.flags == set(['1', '2'])
        assert not notifier.called

    def test_discard_base(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])

        obj.discard('d')

        assert obj.bitflags == 3
        assert obj.flags == set(['1', '2'])

    def test_discard_unknown_flag(self):
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])

        obj.discard('e')

        assert obj.bitflags == 11
        assert obj.flags == set(['1', '2', '8'])

    def test_discard_notify_changed(self, mocker):
        notifier = mocker.Mock()
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b', 'd'])
        obj._notify = notifier

        obj.discard('d')

        assert obj.bitflags == 3
        assert obj.flags == set(['1', '2'])
        notifier.assert_called_once_with()

    def test_discard_notify_unchanged(self, mocker):
        notifier = mocker.Mock()
        obj = enum.FlagSet({'a': 1, 'b': 2, 'c': 4, 'd': 8}, ['a', 'b'])
        obj._notify = notifier

        obj.discard('d')

        assert obj.bitflags == 3
        assert obj.flags == set(['1', '2'])
        assert not notifier.called

    def test_notify(self):
        obj = enum.FlagSet([1, 2, 4, 8])

        obj.notify('notifier')

        assert obj._notify == 'notifier'


class TestEnumAttr(object):
    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            enum.attrs.InvalidatingAttr, '__init__', return_value=None
        )

        result = enum.EnumAttr('eset')

        assert result.eset == 'eset'
        mock_init.assert_called_once_with('invalidate')

    def test_init_other(self, mocker):
        mock_init = mocker.patch.object(
            enum.attrs.InvalidatingAttr, '__init__', return_value=None
        )

        result = enum.EnumAttr('eset', 'other')

        assert result.eset == 'eset'
        mock_init.assert_called_once_with('other')

    def test_prepare_base(self):
        obj = enum.EnumAttr({'a': 1, 'b': 2, 'c': 3})

        result = obj.prepare('instance', 'b')

        assert result == 2

    def test_prepare_unknown(self):
        obj = enum.EnumAttr({'a': 1, 'b': 2, 'c': 3})

        with pytest.raises(AttributeError):
            obj.prepare('instance', 'e')


class TestFlagSetAttr(object):
    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            enum.attrs.InvalidatingAttr, '__init__', return_value=None
        )

        result = enum.FlagSetAttr('eset')

        assert result.eset == 'eset'
        mock_init.assert_called_once_with('invalidate')

    def test_init_other(self, mocker):
        mock_init = mocker.patch.object(
            enum.attrs.InvalidatingAttr, '__init__', return_value=None
        )

        result = enum.FlagSetAttr('eset', 'other')

        assert result.eset == 'eset'
        mock_init.assert_called_once_with('other')

    def test_prepare_none(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            enum.FlagSetAttr, 'get_invalidate'
        )
        notifier = mock_get_invalidate.return_value
        eset = mocker.Mock()
        flagset = eset.flagset.return_value
        obj = enum.FlagSetAttr(eset)

        result = obj.prepare('instance', None)

        assert result == flagset
        eset.flagset.assert_called_once_with()
        mock_get_invalidate.assert_called_once_with('instance')
        flagset.notify.assert_called_once_with(notifier)

    def test_prepare_flags_found(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            enum.FlagSetAttr, 'get_invalidate'
        )
        notifier = mock_get_invalidate.return_value
        eset = mocker.Mock()
        flagset = eset.flagset.return_value
        obj = enum.FlagSetAttr(eset)

        result = obj.prepare('instance', 'flags')

        assert result == flagset
        eset.flagset.assert_called_once_with('flags')
        mock_get_invalidate.assert_called_once_with('instance')
        flagset.notify.assert_called_once_with(notifier)

    def test_prepare_flags_missing(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            enum.FlagSetAttr, 'get_invalidate'
        )
        eset = mocker.Mock(**{
            'flagset.side_effect': TypeError('test'),
        })
        obj = enum.FlagSetAttr(eset)

        with pytest.raises(AttributeError):
            obj.prepare('instance', 'flags')
        eset.flagset.assert_called_once_with('flags')
        assert not mock_get_invalidate.called

    def test_prepare_flagset_match(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            enum.FlagSetAttr, 'get_invalidate'
        )
        notifier = mock_get_invalidate.return_value
        eset = mocker.Mock()
        flagset = mocker.Mock(spec=enum.FlagSet, eset=eset)
        obj = enum.FlagSetAttr(eset)

        result = obj.prepare('instance', flagset)

        assert result == flagset
        assert not eset.flagset.called
        mock_get_invalidate.assert_called_once_with('instance')
        flagset.notify.assert_called_once_with(notifier)

    def test_prepare_flagset_mismatch(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            enum.FlagSetAttr, 'get_invalidate'
        )
        eset = mocker.Mock()
        flagset = mocker.Mock(spec=enum.FlagSet, eset='other')
        obj = enum.FlagSetAttr(eset)

        with pytest.raises(AttributeError):
            obj.prepare('instance', flagset)
        assert not eset.flagset.called
        assert not mock_get_invalidate.called
        assert not flagset.notify.called
