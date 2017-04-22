import uuid

from hum_proto.protocols import connection


class TestConnectionState(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            connection.ConnectionState, '__init__', return_value=None
        )
        node_id = uuid.uuid4()
        payload = b'\200\377\0\0' + node_id.bytes

        result = connection.ConnectionState._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, connection.ConnectionState)
        mock_init.assert_called_once_with(
            mocker.ANY, 255, node_id,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert int(mock_init.call_args[0][0]) == 0x80

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            connection.message.Message, '__init__', return_value=None
        )

        result = connection.ConnectionState(a=1, b=2, c=3)

        assert int(result.flags) == 0x0
        assert int(result.status) == 0
        assert result.node_id == uuid.UUID('0' * 32)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            connection.message.Message, '__init__', return_value=None
        )
        node_id = uuid.uuid4()

        result = connection.ConnectionState(
            'client', 'ERROR', str(node_id), a=1, b=2, c=3
        )

        assert int(result.flags) == 0x80
        assert int(result.status) == 255
        assert result.node_id == node_id
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        node_id = uuid.uuid4()
        obj = connection.ConnectionState('client', 'ERROR', node_id)

        result = obj._encode()

        assert result == b'\200\377\0\0' + node_id.bytes

    def test_node_id_none(self):
        result = connection.ConnectionState.node_id.prepare('instance', None)

        assert result == uuid.UUID('0' * 32)

    def test_node_id_str(self):
        node_id = uuid.uuid4()

        result = connection.ConnectionState.node_id.prepare(
            'instance', str(node_id)
        )

        assert result == node_id

    def test_node_id_uuid(self):
        node_id = uuid.uuid4()

        result = connection.ConnectionState.node_id.prepare(
            'instance', node_id
        )

        assert result is node_id


class TypeForTest(object):
    pass


class TestConnectionError(object):
    def test_decode_0(self, mocker):
        mock_init = mocker.patch.object(
            connection.ConnectionError, '__init__', return_value=None
        )
        payload = b'\0'

        result = connection.ConnectionError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, connection.ConnectionError)
        mock_init.assert_called_once_with(
            0, None,
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_decode_1(self, mocker):
        mock_init = mocker.patch.object(
            connection.ConnectionError, '__init__', return_value=None
        )
        payload = b'\1\5'

        result = connection.ConnectionError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, connection.ConnectionError)
        mock_init.assert_called_once_with(
            1, (5,),
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            connection.message.Message, '__init__', return_value=None
        )

        result = connection.ConnectionError(a=1, b=2, c=3)

        assert int(result.error) == 0
        assert result.args is None
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            connection.message.Message, '__init__', return_value=None
        )

        result = connection.ConnectionError(1, (5,), a=1, b=2, c=3)

        assert int(result.error) == 1
        assert result.args == (5,)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode_0(self):
        obj = connection.ConnectionError(0, None)

        result = obj._encode()

        assert result == b'\0'

    def test_encode_1(self):
        obj = connection.ConnectionError(1, (5,))

        result = obj._encode()

        assert result == b'\1\5'

    def test_args_none(self, mocker):
        instance = mocker.Mock(error=0, _args={})

        result = connection.ConnectionError.args.prepare(instance, None)

        assert result is None

    def test_args_noenc(self, mocker):
        instance = mocker.Mock(error=0, _args={})

        result = connection.ConnectionError.args.prepare(instance, ('spam',))

        assert result is None

    def test_args_convert(self, mocker):
        mock_init = mocker.patch.object(
            TypeForTest, '__init__', return_value=None
        )
        instance = mocker.Mock(
            error=0,
            _args={
                0: connection.ErrorData(TypeForTest, 'spam'),
            },
        )

        result = connection.ConnectionError.args.prepare(instance, ('spam',))

        assert isinstance(result, TypeForTest)
        mock_init.assert_called_once_with('spam')

    def test_args_noconvert(self, mocker):
        arg = TypeForTest()
        mock_init = mocker.patch.object(
            TypeForTest, '__init__', return_value=None
        )
        instance = mocker.Mock(
            error=0,
            _args={
                0: connection.ErrorData(TypeForTest, 'spam'),
            },
        )

        result = connection.ConnectionError.args.prepare(instance, arg)

        assert result is arg
        assert not mock_init.called


class TestProtocol0(object):
    def test_base(self, mocker):
        mock_ConnectionError = mocker.patch.object(
            connection, 'ConnectionError'
        )
        mock_ConnectionState = mocker.patch.object(
            connection, 'ConnectionState'
        )
        mock_RequestConnectionState = mocker.patch.object(
            connection, 'RequestConnectionState'
        )
        flags = connection.message.Message.carrier_flags.eset.flagset()

        result = connection._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_RequestConnectionState.return_value
        assert not mock_ConnectionError._decode.called
        assert not mock_ConnectionState._decode.called
        mock_RequestConnectionState.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )

    def test_error(self, mocker):
        mock_ConnectionError = mocker.patch.object(
            connection, 'ConnectionError'
        )
        mock_ConnectionState = mocker.patch.object(
            connection, 'ConnectionState'
        )
        mock_RequestConnectionState = mocker.patch.object(
            connection, 'RequestConnectionState'
        )
        flags = connection.message.Message.carrier_flags.eset.flagset('error')

        result = connection._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_ConnectionError._decode.return_value
        mock_ConnectionError._decode.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_ConnectionState._decode.called
        assert not mock_RequestConnectionState.called

    def test_state(self, mocker):
        mock_ConnectionError = mocker.patch.object(
            connection, 'ConnectionError'
        )
        mock_ConnectionState = mocker.patch.object(
            connection, 'ConnectionState'
        )
        mock_RequestConnectionState = mocker.patch.object(
            connection, 'RequestConnectionState'
        )
        flags = connection.message.Message.carrier_flags.eset.flagset('reply')

        result = connection._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_ConnectionState._decode.return_value
        assert not mock_ConnectionError._decode.called
        mock_ConnectionState._decode.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_RequestConnectionState.called
