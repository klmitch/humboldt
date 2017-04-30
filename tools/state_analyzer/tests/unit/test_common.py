from state_analyzer import common


class TestCachedProperty(object):
    def test_init(self, mocker):
        mock_update_wrapper = mocker.patch.object(
            common.functools, 'update_wrapper'
        )

        result = common.CachedProperty('func')

        assert result.func == 'func'
        assert result.attr == '_cached_property_%x' % id(result)
        mock_update_wrapper.assert_called_once_with(result, 'func')

    def test_get_asclass(self, mocker):
        func = mocker.Mock(__name__='func', return_value='value')
        obj = common.CachedProperty(func)

        result = obj.__get__(None, 'owner')

        assert result is obj
        assert not func.called

    def test_get_cached(self, mocker):
        func = mocker.Mock(__name__='func', return_value='value')
        obj = common.CachedProperty(func)
        instance = mocker.Mock()
        setattr(instance, obj.attr, 'cached')

        result = obj.__get__(instance, 'owner')

        assert result == 'cached'
        assert getattr(instance, obj.attr) == 'cached'
        assert not func.called

    def test_get_uncached(self, mocker):
        func = mocker.Mock(__name__='func', return_value='value')
        obj = common.CachedProperty(func)
        instance = mocker.Mock()
        delattr(instance, obj.attr)

        result = obj.__get__(instance, 'owner')

        assert result == 'value'
        assert getattr(instance, obj.attr) == 'value'
        func.assert_called_once_with(instance)

    def test_set(self, mocker):
        func = mocker.Mock(__name__='func')
        obj = common.CachedProperty(func)
        instance = mocker.Mock()
        setattr(instance, obj.attr, 'random')

        obj.__set__(instance, 'value')

        assert getattr(instance, obj.attr) == 'value'

    def test_delete_set(self, mocker):
        func = mocker.Mock(__name__='func')
        obj = common.CachedProperty(func)
        instance = mocker.Mock()
        setattr(instance, obj.attr, 'random')

        obj.__delete__(instance)

        assert not hasattr(instance, obj.attr)

    def test_delete_unset(self, mocker):
        func = mocker.Mock(__name__='func')
        obj = common.CachedProperty(func)
        instance = mocker.Mock()
        delattr(instance, obj.attr)

        obj.__delete__(instance)

        assert not hasattr(instance, obj.attr)
