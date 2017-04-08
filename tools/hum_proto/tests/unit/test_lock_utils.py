from hum_proto import lock_utils


class RWInnerForTest(lock_utils.RWInner):
    def predicate(self, other):
        pass

    def signaler(self, other):
        pass


class TestRWInner(object):
    def test_init(self, mocker):
        mock_Condition = mocker.patch.object(
            lock_utils.threading, 'Condition'
        )

        result = RWInnerForTest('lock')

        assert result.cond == mock_Condition.return_value
        assert result.active == 0
        assert result.waiting == 0
        mock_Condition.assert_called_once_with('lock')


class TestRWReader(object):
    def test_predicate_base(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=0)
        obj = lock_utils.RWReader('lock')

        result = obj.predicate(other)

        assert result is False

    def test_predicate_active(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=1)
        obj = lock_utils.RWReader('lock')

        result = obj.predicate(other)

        assert result is True

    def test_signaler_base(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(waiting=0)
        obj = lock_utils.RWReader('lock')
        obj.active = 1

        obj.signaler(other)

        assert not other.cond.notify.called

    def test_signaler_reader_active(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(waiting=0)
        obj = lock_utils.RWReader('lock')

        obj.signaler(other)

        assert not other.cond.notify.called

    def test_signaler_writer_waiting(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(waiting=1)
        obj = lock_utils.RWReader('lock')
        obj.active = 1

        obj.signaler(other)

        assert not other.cond.notify.called

    def test_signaler_signaled(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(waiting=1)
        obj = lock_utils.RWReader('lock')

        obj.signaler(other)

        other.cond.notify.assert_called_once_with()


class TestRWWriter(object):
    def test_predicate_base(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=0)
        obj = lock_utils.RWWriter('lock')

        result = obj.predicate(other)

        assert result is False

    def test_predicate_writer_active(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=0)
        obj = lock_utils.RWWriter('lock')
        obj.active = 1

        result = obj.predicate(other)

        assert result is True

    def test_predicate_reader_active(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=1)
        obj = lock_utils.RWWriter('lock')

        result = obj.predicate(other)

        assert result is True

    def test_predicate_both_active(self, mocker):
        mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        other = mocker.Mock(active=1)
        obj = lock_utils.RWWriter('lock')
        obj.active = 1

        result = obj.predicate(other)

        assert result is True

    def test_signaler_base(self, mocker):
        mock_Condition = mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        cond = mock_Condition.return_value
        other = mocker.Mock(waiting=0)
        obj = lock_utils.RWWriter('lock')
        obj.waiting = 0

        obj.signaler(other)

        assert not cond.notify.called
        assert not other.cond.notify_all.called

    def test_signaler_reader_waiting(self, mocker):
        mock_Condition = mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        cond = mock_Condition.return_value
        other = mocker.Mock(waiting=1)
        obj = lock_utils.RWWriter('lock')
        obj.waiting = 1

        obj.signaler(other)

        assert not cond.notify.called
        other.cond.notify_all.assert_called_once_with()

    def test_signaler_writer_waiting(self, mocker):
        mock_Condition = mocker.patch.object(
            lock_utils.threading, 'Condition'
        )
        cond = mock_Condition.return_value
        other = mocker.Mock(waiting=0)
        obj = lock_utils.RWWriter('lock')
        obj.waiting = 1

        obj.signaler(other)

        cond.notify.assert_called_once_with()
        assert not other.cond.notify_all.called


class TestLocker(object):
    def test_init(self):
        result = lock_utils.Locker('lock', 'me', 'other')

        assert result._lock == 'lock'
        assert result._me == 'me'
        assert result._other == 'other'

    def test_enter_no_waiting(self, mocker):
        lock = mocker.MagicMock()
        me = mocker.Mock(**{
            'waiting': 0,
            'active': 0,
            'predicate.return_value': False,
        })
        obj = lock_utils.Locker(lock, me, 'other')

        result = obj.__enter__()

        assert result is obj
        assert me.waiting == 0
        assert me.active == 1
        lock.__enter__.assert_called_once_with()
        me.predicate.assert_called_once_with('other')
        assert not me.cond.wait.called
        lock.__exit__.assert_called_once_with(None, None, None)

    def test_enter_waiting(self, mocker):
        def fake_predicate(other):
            expected, retval = other.pop(0)
            assert me.waiting == expected
            return retval
        lock = mocker.MagicMock()
        me = mocker.Mock(**{
            'waiting': 0,
            'active': 0,
            'predicate.side_effect': fake_predicate,
        })
        other = [(0, True), (1, True), (1, True), (1, False)]
        obj = lock_utils.Locker(lock, me, other)

        result = obj.__enter__()

        assert result is obj
        assert me.waiting == 0
        assert me.active == 1
        lock.__enter__.assert_called_once_with()
        me.predicate.assert_has_calls([
            mocker.call(other),
            mocker.call(other),
            mocker.call(other),
            mocker.call(other),
        ])
        assert me.predicate.call_count == 4
        me.cond.wait.assert_has_calls([
            mocker.call(),
            mocker.call(),
        ])
        assert me.cond.wait.call_count == 2
        lock.__exit__.assert_called_once_with(None, None, None)

    def test_exit(self, mocker):
        lock = mocker.MagicMock()
        me = mocker.Mock(active=1)
        obj = lock_utils.Locker(lock, me, 'other')

        result = obj.__exit__(None, None, None)

        assert result is None
        assert me.active == 0
        lock.__enter__.assert_called_once_with()
        me.signaler.assert_called_once_with('other')
        lock.__exit__.assert_called_once_with(None, None, None)


class TestRWLock(object):
    def test_init(self, mocker):
        mock_Lock = mocker.patch.object(lock_utils.threading, 'Lock')
        mock_RWReader = mocker.patch.object(lock_utils, 'RWReader')
        mock_RWWriter = mocker.patch.object(lock_utils, 'RWWriter')
        mock_Locker = mocker.patch.object(
            lock_utils, 'Locker', side_effect=['read', 'write']
        )

        result = lock_utils.RWLock()

        assert result._read == mock_RWReader.return_value
        assert result._write == mock_RWWriter.return_value
        assert result._read_locker == 'read'
        assert result._write_locker == 'write'
        mock_Lock.assert_called_once_with()
        mock_RWReader.assert_called_once_with(mock_Lock.return_value)
        mock_RWWriter.assert_called_once_with(mock_Lock.return_value)
        mock_Locker.assert_has_calls([
            mocker.call(mock_Lock.return_value, result._read, result._write),
            mocker.call(mock_Lock.return_value, result._write, result._read),
        ])
        assert mock_Locker.call_count == 2

    def test_read(self, mocker):
        mocker.patch.object(lock_utils.threading, 'Lock')
        mocker.patch.object(lock_utils, 'RWReader')
        mocker.patch.object(lock_utils, 'RWWriter')
        mocker.patch.object(
            lock_utils, 'Locker', side_effect=['read', 'write']
        )
        obj = lock_utils.RWLock()

        assert obj.read == 'read'

    def test_write(self, mocker):
        mocker.patch.object(lock_utils.threading, 'Lock')
        mocker.patch.object(lock_utils, 'RWReader')
        mocker.patch.object(lock_utils, 'RWWriter')
        mocker.patch.object(
            lock_utils, 'Locker', side_effect=['read', 'write']
        )
        obj = lock_utils.RWLock()

        assert obj.write == 'write'
