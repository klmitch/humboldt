import pytest

from hum_proto import attrs


class TestInvalidatingAttr(object):
    def test_init_base(self):
        result = attrs.InvalidatingAttr()

        assert result.invalidator == 'invalidate'
        assert result._attr_name == '_inval_attr_%d' % id(result)
        assert result.attr_name is None

    def test_init_alt(self):
        result = attrs.InvalidatingAttr('other')

        assert result.invalidator == 'other'
        assert result._attr_name == '_inval_attr_%d' % id(result)
        assert result.attr_name is None

    def test_prepare(self):
        obj = attrs.InvalidatingAttr()

        result = obj.prepare('instance', 'value')

        assert result == 'value'

    def test_get_invalidate_base(self, mocker):
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()

        result = obj.get_invalidate(instance)

        assert result == instance.invalidate

    def test_get_invalidate_alt(self, mocker):
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr('other')

        result = obj.get_invalidate(instance)

        assert result == instance.other

    def test_get_class(self):
        obj = attrs.InvalidatingAttr()

        result = obj.__get__(None, 'class')

        assert result is obj

    def test_get_instance(self, mocker):
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()

        result = obj.__get__(instance, 'class')

        assert result == getattr(instance, obj._attr_name)

    def test_get_instance_unset(self, mocker):
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()
        delattr(instance, obj._attr_name)

        with pytest.raises(AttributeError):
            obj.__get__(instance, 'class')

    def test_set_base(self, mocker):
        mock_prepare = mocker.patch.object(
            attrs.InvalidatingAttr, 'prepare', return_value='xlated'
        )
        mock_get_invalidate = mocker.patch.object(
            attrs.InvalidatingAttr, 'get_invalidate'
        )
        invalidate = mock_get_invalidate.return_value
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()

        obj.__set__(instance, 'value')

        assert getattr(instance, obj._attr_name) == 'xlated'
        mock_prepare.assert_called_once_with(instance, 'value')
        mock_get_invalidate.assert_called_once_with(instance)
        invalidate.assert_called_once_with()

    def test_set_unset(self, mocker):
        mock_prepare = mocker.patch.object(
            attrs.InvalidatingAttr, 'prepare', return_value='xlated'
        )
        mock_get_invalidate = mocker.patch.object(
            attrs.InvalidatingAttr, 'get_invalidate'
        )
        invalidate = mock_get_invalidate.return_value
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()
        delattr(instance, obj._attr_name)

        obj.__set__(instance, 'value')

        assert getattr(instance, obj._attr_name) == 'xlated'
        mock_prepare.assert_called_once_with(instance, 'value')
        mock_get_invalidate.assert_called_once_with(instance)
        invalidate.assert_called_once_with()

    def test_set_unchanged(self, mocker):
        mock_prepare = mocker.patch.object(
            attrs.InvalidatingAttr, 'prepare', return_value='xlated'
        )
        mock_get_invalidate = mocker.patch.object(
            attrs.InvalidatingAttr, 'get_invalidate'
        )
        invalidate = mock_get_invalidate.return_value
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()
        setattr(instance, obj._attr_name, 'xlated')

        obj.__set__(instance, 'value')

        assert getattr(instance, obj._attr_name) == 'xlated'
        mock_prepare.assert_called_once_with(instance, 'value')
        assert not mock_get_invalidate.called
        assert not invalidate.called

    def test_delete_base(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            attrs.InvalidatingAttr, 'get_invalidate'
        )
        invalidate = mock_get_invalidate.return_value
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()

        obj.__delete__(instance)

        assert not hasattr(instance, obj._attr_name)
        mock_get_invalidate.assert_called_once_with(instance)
        invalidate.assert_called_once_with()

    def test_delete_unset(self, mocker):
        mock_get_invalidate = mocker.patch.object(
            attrs.InvalidatingAttr, 'get_invalidate'
        )
        invalidate = mock_get_invalidate.return_value
        instance = mocker.Mock()
        obj = attrs.InvalidatingAttr()
        delattr(instance, obj._attr_name)

        with pytest.raises(AttributeError):
            obj.__delete__(instance)
        assert not hasattr(instance, obj._attr_name)
        assert not mock_get_invalidate.called
        assert not invalidate.called


class TestFilterAttr(object):
    def test_init(self, mocker):
        func = mocker.Mock()
        result = attrs.FilterAttr(func)

        assert result.prepare == func

    def test_prepare(self, mocker):
        func = mocker.Mock()
        obj = attrs.FilterAttr(func)

        result = obj.prepare('instance', 'value')

        assert result == func.return_value
        func.assert_called_once_with('instance', 'value')


class TestInvalidatingAttrMeta(object):
    def test_init(self):
        some_object = object()
        namespace = {
            'attr1': 'some value',
            'attr2': some_object,
            'attr3': attrs.InvalidatingAttr(),
            'attr4': attrs.InvalidatingAttr(),
        }
        result = attrs.InvalidatingAttrMeta('name', (object,), namespace)

        assert result.attr1 == 'some value'
        assert result.attr2 is some_object
        assert isinstance(result.attr3, attrs.InvalidatingAttr)
        assert result.attr3.attr_name == 'attr3'
        assert isinstance(result.attr4, attrs.InvalidatingAttr)
        assert result.attr4.attr_name == 'attr4'
