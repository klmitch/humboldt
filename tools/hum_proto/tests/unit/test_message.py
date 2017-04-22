import uuid

import pytest

from hum_proto import message


class ExceptionForTest(Exception):
    pass


class TestFlagger(object):
    def test_int(self):
        result = message._flagger('1234')

        assert result == 1234

    def test_str(self):
        result = message._flagger('1, 2, 3')

        assert result == ['1', '2', '3']


class TestEnumer(object):
    def test_int(self):
        result = message._enumer('1234')

        assert result == 1234

    def test_str(self):
        result = message._enumer('other')

        assert result == 'other'


class TestByter(object):
    def test_base(self):
        result = message._byter('this is a test')

        assert result == b'this is a test'

    def test_escapes(self):
        result = message._byter('\\\'\\"\\a\\b\\f\\n\\r\\t\\v\\xff'
                                '\\1\\12\\123\\1234\\\\\\o')

        assert result == b'\'"\a\b\f\n\r\t\v\xff\x01\x0a\x53\x534\\\\o'

    def test_badhex(self):
        with pytest.raises(ValueError):
            message._byter('\\x')
        with pytest.raises(ValueError):
            message._byter('\\x1')
        with pytest.raises(ValueError):
            message._byter('\\x1z')

    def test_octoverflow(self):
        result = message._byter('\\377\\400')

        assert result == b'\377\40\60'


class TestSplitter(object):
    def test_base(self):
        result = message._splitter('1, 2, 3')

        assert result == ['1', '2', '3']


class TestRecvAll(object):
    def test_simple(self, mocker):
        sock = mocker.Mock(**{
            'recv.return_value': b'1234567890',
        })

        result = message._recvall(sock, 10)

        assert result == b'1234567890'

    def test_fragmented(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': [
                b'1234',
                b'567',
                b'890',
            ],
        })

        result = message._recvall(sock, 10)

        assert result == b'1234567890'

    def test_short(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': [
                b'1234',
                b'567',
                b'',
            ],
        })

        result = message._recvall(sock, 10)

        assert result == b'1234567'


class TestMessage(object):
    def test_recv_header_only(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert isinstance(result, message.Message)
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        mock_init.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'',
            _bytes=b'\0\0\0\4',
        )
        flags = mock_init.call_args[1]['carrier_flags']
        assert isinstance(flags, message.enum.FlagSet)
        assert int(flags) == 0

    def test_recv_vers_flags(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\70\3\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert isinstance(result, message.Message)
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        mock_init.assert_called_once_with(
            carrier_version=3,
            carrier_flags=mocker.ANY,
            protocol=3,
            payload=b'',
            _bytes=b'\70\3\0\4',
        )
        flags = mock_init.call_args[1]['carrier_flags']
        assert isinstance(flags, message.enum.FlagSet)
        assert int(flags) == 0x8

    def test_recv_with_payload(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a test',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert isinstance(result, message.Message)
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        mock_init.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'this is a test',
            _bytes=b'\0\0\0\22this is a test',
        )

    def test_recv_header_only_short(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result is None
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        assert not mock_init.called

    def test_recv_header_only_closed(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=None
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result is None
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        assert not mock_init.called

    def test_recv_with_payload_short(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a t',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result is None
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        assert not mock_init.called

    def test_recv_with_payload_closed(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                None,
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result is None
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        assert not mock_init.called

    def test_recv_header_only_registered(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        proto = mocker.Mock()
        message.Message._decoders[0] = proto
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result == proto.return_value
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        assert not mock_init.called
        proto.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'',
            _bytes=b'\0\0\0\4',
        )

    def test_recv_with_payload_registered(self, mocker):
        mocker.patch.object(message.Message, '_decoders', {})
        proto = mocker.Mock()
        message.Message._decoders[0] = proto
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a test',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.recv('sock')

        assert result == proto.return_value
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        assert not mock_init.called
        proto.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'this is a test',
            _bytes=b'\0\0\0\22this is a test',
        )

    def test_interpret_base(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(),
                'd': mocker.Mock(),
            },
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        result = message.Message.interpret(['msg', 'test', 'a=1', 'c=3'])

        assert result == type_.return_value
        type_._carrier_attrs['a'].assert_called_once_with('1')
        assert not type_._carrier_attrs['b'].called
        type_.MSG_ATTRS['c'].assert_called_once_with('3')
        assert not type_.MSG_ATTRS['d'].called
        type_.assert_called_once_with(
            a=type_._carrier_attrs['a'].return_value,
            c=type_.MSG_ATTRS['c'].return_value,
        )

    def test_interpret_no_params(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(),
                'd': mocker.Mock(),
            },
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        result = message.Message.interpret(['msg', 'test'])

        assert result == type_.return_value
        assert not type_._carrier_attrs['a'].called
        assert not type_._carrier_attrs['b'].called
        assert not type_.MSG_ATTRS['c'].called
        assert not type_.MSG_ATTRS['d'].called
        type_.assert_called_once_with()

    def test_interpret_no_message(self, mocker):
        mocker.patch.object(message.Message, '_classes', {})

        with pytest.raises(message.CommandError):
            message.Message.interpret(['msg', 'test'])

    def test_interpret_missing_parameter_value(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(),
                'd': mocker.Mock(),
            },
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        with pytest.raises(message.CommandError):
            message.Message.interpret(['msg', 'test', 'a=1', 'b', 'c=3'])
        type_._carrier_attrs['a'].assert_called_once_with('1')
        assert not type_._carrier_attrs['b'].called
        assert not type_.MSG_ATTRS['c'].called
        assert not type_.MSG_ATTRS['d'].called
        assert not type_.called

    def test_interpret_unknown_parameter(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(),
                'd': mocker.Mock(),
            },
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        with pytest.raises(message.CommandError):
            message.Message.interpret(['msg', 'test', 'a=1', 'e=5'])
        type_._carrier_attrs['a'].assert_called_once_with('1')
        assert not type_._carrier_attrs['b'].called
        assert not type_.MSG_ATTRS['c'].called
        assert not type_.MSG_ATTRS['d'].called
        assert not type_.called

    def test_interpret_bad_parameter_value(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(side_effect=ValueError('oops')),
                'd': mocker.Mock(),
            },
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        with pytest.raises(message.CommandError):
            message.Message.interpret(['msg', 'test', 'a=1', 'c=3'])
        type_._carrier_attrs['a'].assert_called_once_with('1')
        assert not type_._carrier_attrs['b'].called
        type_.MSG_ATTRS['c'].assert_called_once_with('3')
        assert not type_.MSG_ATTRS['d'].called
        assert not type_.called

    def test_interpret_failure(self, mocker):
        type_ = mocker.Mock(
            __name__='MsgTest',
            _carrier_attrs={
                'a': mocker.Mock(),
                'b': mocker.Mock(),
            },
            MSG_ATTRS={
                'c': mocker.Mock(),
                'd': mocker.Mock(),
            },
            side_effect=ValueError('oops'),
        )
        mocker.patch.object(message.Message, '_classes', {'msgtest': type_})

        with pytest.raises(message.CommandError):
            message.Message.interpret(['msg', 'test', 'a=1', 'c=3'])
        type_._carrier_attrs['a'].assert_called_once_with('1')
        assert not type_._carrier_attrs['b'].called
        type_.MSG_ATTRS['c'].assert_called_once_with('3')
        assert not type_.MSG_ATTRS['d'].called
        type_.assert_called_once_with(
            a=type_._carrier_attrs['a'].return_value,
            c=type_.MSG_ATTRS['c'].return_value,
        )

    def test_init_base(self):
        result = message.Message(
            carrier_version='carrier_version',
            carrier_flags=0x8,
            protocol='protocol',
            payload='payload',
            _bytes='_bytes',
        )

        assert result._carrier_version == 'carrier_version'
        assert int(result.carrier_flags) == 0x8
        assert result._protocol == 'protocol'
        assert result._payload == 'payload'
        assert result._bytes == '_bytes'

    def test_init_default_flags(self, mocker):
        mocker.patch.object(
            message.Message, 'default_carrier_flags', 'reply'
        )
        result = message.Message(
            carrier_version='carrier_version',
            protocol='protocol',
            payload='payload',
            _bytes='_bytes',
        )

        assert result._carrier_version == 'carrier_version'
        assert int(result.carrier_flags) == 0x8
        assert result._protocol == 'protocol'
        assert result._payload == 'payload'
        assert result._bytes == '_bytes'

    def test_len(self, mocker):
        mocker.patch.object(message.Message, 'bytes', b'1234')
        obj = message.Message()

        assert len(obj) == 4

    def test_repr(self, mocker):
        mocker.patch.object(message.Message, 'MSG_ATTRS', ['payload', 'other'])
        mocker.patch.object(message.Message, '__len__', return_value=8)
        mocker.patch.object(message.Message, 'carrier_version', 3)
        mocker.patch.object(message.Message, 'protocol', 2)
        mocker.patch.object(message.Message, 'payload', b'payload')
        obj = message.Message()
        obj.other = 'spam'

        result = repr(obj)

        assert result == (
            '<Message size=8, carrier_version=3, '
            'carrier_flags=<FlagSet [] (0x0)>, protocol=2, payload=%r, '
            'other=%r>' % (b'payload', 'spam')
        )

    def test_invalidate_bytes(self):
        obj = message.Message(_bytes=b'test')

        obj._invalidate_bytes()

        assert obj._bytes is None

    def test_encode_internal(self):
        obj = message.Message()

        result = obj._encode()

        assert result == b''

    def test_invalidate(self):
        obj = message.Message(_bytes=b'test', payload=b'test2')

        obj.invalidate()

        assert obj._payload is None
        assert obj._bytes is None

    def test_send(self, mocker):
        mocker.patch.object(message.Message, 'bytes', b'1234')
        sock = mocker.Mock()
        obj = message.Message()

        obj.send(sock)

        sock.sendall.assert_called_once_with(b'1234')

    def test_carrier_version_default(self):
        obj = message.Message()

        assert obj.carrier_version == 0

    def test_carrier_version_explicit(self):
        obj = message.Message(carrier_version=3)

        assert obj.carrier_version == 3

    def test_protocol_base(self):
        obj = message.Message()

        assert obj.protocol == 0

    def test_protocol_default(self, mocker):
        mocker.patch.object(message.Message, 'PROTOCOL', 3, create=True)
        obj = message.Message()

        assert obj.protocol == 3

    def test_protocol_explicit(self):
        obj = message.Message(protocol=3)

        assert obj.protocol == 3

    def test_protocol_explicit_overrides_default(self, mocker):
        mocker.patch.object(message.Message, 'PROTOCOL', 2, create=True)
        obj = message.Message(protocol=3)

        assert obj.protocol == 3

    def test_payload_cached(self, mocker):
        mock_encode = mocker.patch.object(
            message.Message, '_encode', return_value=b'payload'
        )
        obj = message.Message(payload=b'cached')

        assert obj.payload == b'cached'
        assert obj._payload == b'cached'
        assert not mock_encode.called

    def test_payload_uncached(self, mocker):
        mock_encode = mocker.patch.object(
            message.Message, '_encode', return_value=b'payload'
        )
        obj = message.Message()

        assert obj.payload == b'payload'
        assert obj._payload == b'payload'
        mock_encode.assert_called_once_with()

    def test_bytes_cached(self, mocker):
        mocker.patch.object(message.Message, 'carrier_version', 3)
        mocker.patch.object(message.Message, 'protocol', 5)
        mocker.patch.object(message.Message, 'payload', b'payload')
        obj = message.Message(carrier_flags='reply', _bytes=b'cached')

        assert obj.bytes == b'cached'
        assert obj._bytes == b'cached'

    def test_bytes_uncached(self, mocker):
        mocker.patch.object(message.Message, 'carrier_version', 3)
        mocker.patch.object(message.Message, 'protocol', 5)
        mocker.patch.object(message.Message, 'payload', b'payload')
        obj = message.Message(carrier_flags='reply')

        assert obj.bytes == b'\70\5\0\13payload'
        assert obj._bytes == b'\70\5\0\13payload'


class TestConnectionState(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            message.ConnectionState, '__init__', return_value=None
        )
        node_id = uuid.uuid4()
        payload = b'\200\377\0\0' + node_id.bytes

        result = message.ConnectionState._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.ConnectionState)
        mock_init.assert_called_once_with(
            mocker.ANY, 255, node_id,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert int(mock_init.call_args[0][0]) == 0x80

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.ConnectionState(a=1, b=2, c=3)

        assert int(result.flags) == 0x0
        assert int(result.status) == 0
        assert result.node_id == uuid.UUID('0' * 32)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )
        node_id = uuid.uuid4()

        result = message.ConnectionState(
            'client', 'ERROR', str(node_id), a=1, b=2, c=3
        )

        assert int(result.flags) == 0x80
        assert int(result.status) == 255
        assert result.node_id == node_id
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        node_id = uuid.uuid4()
        obj = message.ConnectionState('client', 'ERROR', node_id)

        result = obj._encode()

        assert result == b'\200\377\0\0' + node_id.bytes

    def test_node_id_none(self):
        result = message.ConnectionState.node_id.prepare('instance', None)

        assert result == uuid.UUID('0' * 32)

    def test_node_id_str(self):
        node_id = uuid.uuid4()

        result = message.ConnectionState.node_id.prepare(
            'instance', str(node_id)
        )

        assert result == node_id

    def test_node_id_uuid(self):
        node_id = uuid.uuid4()

        result = message.ConnectionState.node_id.prepare('instance', node_id)

        assert result is node_id


class TypeForTest(object):
    pass


class TestConnectionError(object):
    def test_decode_0(self, mocker):
        mock_init = mocker.patch.object(
            message.ConnectionError, '__init__', return_value=None
        )
        payload = b'\0'

        result = message.ConnectionError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.ConnectionError)
        mock_init.assert_called_once_with(
            0, None,
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_decode_1(self, mocker):
        mock_init = mocker.patch.object(
            message.ConnectionError, '__init__', return_value=None
        )
        payload = b'\1\5'

        result = message.ConnectionError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.ConnectionError)
        mock_init.assert_called_once_with(
            1, (5,),
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.ConnectionError(a=1, b=2, c=3)

        assert int(result.error) == 0
        assert result.args is None
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.ConnectionError(1, (5,), a=1, b=2, c=3)

        assert int(result.error) == 1
        assert result.args == (5,)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode_0(self):
        obj = message.ConnectionError(0, None)

        result = obj._encode()

        assert result == b'\0'

    def test_encode_1(self):
        obj = message.ConnectionError(1, (5,))

        result = obj._encode()

        assert result == b'\1\5'

    def test_args_none(self, mocker):
        instance = mocker.Mock(error=0, _args={})

        result = message.ConnectionError.args.prepare(instance, None)

        assert result is None

    def test_args_noenc(self, mocker):
        instance = mocker.Mock(error=0, _args={})

        result = message.ConnectionError.args.prepare(instance, ('spam',))

        assert result is None

    def test_args_convert(self, mocker):
        mock_init = mocker.patch.object(
            TypeForTest, '__init__', return_value=None
        )
        instance = mocker.Mock(
            error=0,
            _args={
                0: message.ErrorData(TypeForTest, 'spam'),
            },
        )

        result = message.ConnectionError.args.prepare(instance, ('spam',))

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
                0: message.ErrorData(TypeForTest, 'spam'),
            },
        )

        result = message.ConnectionError.args.prepare(instance, arg)

        assert result is arg
        assert not mock_init.called


class TestProtocol0(object):
    def test_base(self, mocker):
        mock_ConnectionError = mocker.patch.object(message, 'ConnectionError')
        mock_ConnectionState = mocker.patch.object(message, 'ConnectionState')
        mock_RequestConnectionState = mocker.patch.object(
            message, 'RequestConnectionState'
        )
        flags = message.Message.carrier_flags.eset.flagset()

        result = message._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_RequestConnectionState.return_value
        assert not mock_ConnectionError._decode.called
        assert not mock_ConnectionState._decode.called
        mock_RequestConnectionState.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )

    def test_error(self, mocker):
        mock_ConnectionError = mocker.patch.object(message, 'ConnectionError')
        mock_ConnectionState = mocker.patch.object(message, 'ConnectionState')
        mock_RequestConnectionState = mocker.patch.object(
            message, 'RequestConnectionState'
        )
        flags = message.Message.carrier_flags.eset.flagset('error')

        result = message._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_ConnectionError._decode.return_value
        mock_ConnectionError._decode.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_ConnectionState._decode.called
        assert not mock_RequestConnectionState.called

    def test_state(self, mocker):
        mock_ConnectionError = mocker.patch.object(message, 'ConnectionError')
        mock_ConnectionState = mocker.patch.object(message, 'ConnectionState')
        mock_RequestConnectionState = mocker.patch.object(
            message, 'RequestConnectionState'
        )
        flags = message.Message.carrier_flags.eset.flagset('reply')

        result = message._protocol0(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_ConnectionState._decode.return_value
        assert not mock_ConnectionError._decode.called
        mock_ConnectionState._decode.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_RequestConnectionState.called


class TestStartTLSReply(object):
    def test_getpeer_nopeer(self, mocker):
        sock = mocker.Mock(**{
            'getpeercert.return_value': None,
        })
        obj = message.StartTLSReply()

        result = obj._getpeer(sock)

        assert result is None

    def test_getpeer_commonname(self, mocker):
        # Taken straight from the docs
        peercert = {
            'issuer': (
                (('countryName', 'IL'),),
                (('organizationName', 'StartCom Ltd.'),),
                (('organizationalUnitName',
                  'Secure Digital Certificate Signing'),),
                (('commonName',
                  'StartCom Class 2 Primary Intermediate Server CA'),)
            ),
            'notAfter': 'Nov 22 08:15:19 2013 GMT',
            'notBefore': 'Nov 21 03:09:52 2011 GMT',
            'serialNumber': '95F0',
            'subject': (
                (('description', '571208-SLe257oHY9fVQ07Z'),),
                (('countryName', 'US'),),
                (('stateOrProvinceName', 'California'),),
                (('localityName', 'San Francisco'),),
                (('organizationName',
                  'Electronic Frontier Foundation, Inc.'),),
                (('commonName', '*.eff.org'),),
                (('emailAddress', 'hostmaster@eff.org'),)
            ),
            'subjectAltName': (('DNS', '*.eff.org'), ('DNS', 'eff.org')),
            'version': 3,
        }
        sock = mocker.Mock(**{
            'getpeercert.return_value': peercert,
        })
        obj = message.StartTLSReply()

        result = obj._getpeer(sock)

        assert result == '*.eff.org'

    def test_getpeer_distinguishedname(self, mocker):
        # Taken straight from the docs
        peercert = {
            'issuer': (
                (('countryName', 'IL'),),
                (('organizationName', 'StartCom Ltd.'),),
                (('organizationalUnitName',
                  'Secure Digital Certificate Signing'),),
                (('commonName',
                  'StartCom Class 2 Primary Intermediate Server CA'),)
            ),
            'notAfter': 'Nov 22 08:15:19 2013 GMT',
            'notBefore': 'Nov 21 03:09:52 2011 GMT',
            'serialNumber': '95F0',
            'subject': (
                (('description', '571208-SLe257oHY9fVQ07Z'),),
                (('countryName', 'US'),),
                (('stateOrProvinceName', 'California'),),
                (('localityName', 'San Francisco'),),
                (('organizationName',
                  'Electronic Frontier Foundation, Inc.'),),
                (('commonNameAlt', '*.eff.org'), ('UID', '34')),
                (('emailAddress', 'hostmaster@eff.org'),)
            ),
            'subjectAltName': (('DNS', '*.eff.org'), ('DNS', 'eff.org')),
            'version': 3,
        }
        sock = mocker.Mock(**{
            'getpeercert.return_value': peercert,
        })
        obj = message.StartTLSReply()

        result = obj._getpeer(sock)

        assert result == (
            'description=571208-SLe257oHY9fVQ07Z, '
            'countryName=US, '
            'stateOrProvinceName=California, '
            'localityName=San Francisco, '
            'organizationName=Electronic Frontier Foundation, Inc., '
            'commonNameAlt=*.eff.org/UID=34, '
            'emailAddress=hostmaster@eff.org'
        )

    def test_action_failure(self, mocker):
        mock_getpeer = mocker.patch.object(
            message.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock(**{
            'wrap.side_effect': ExceptionForTest('some failure'),
        })
        obj = message.StartTLSReply()

        obj.action(apploop)

        apploop.display.assert_has_calls([
            mocker.call('Initiating TLS (server mode)'),
            mocker.call('TLS exchange failed: some failure'),
        ])
        assert apploop.display.call_count == 2
        apploop.wrap.assert_called_once_with(
            apploop.sslctx_srv.wrap_socket, server_side=True
        )
        assert not mock_getpeer.called

    def test_action_nopeer(self, mocker):
        mock_getpeer = mocker.patch.object(
            message.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock()
        obj = message.StartTLSReply()

        obj.action(apploop)

        apploop.display.assert_has_calls([
            mocker.call('Initiating TLS (server mode)'),
            mocker.call('TLS exchange succeeded; no peer information'),
        ])
        assert apploop.display.call_count == 2
        apploop.wrap.assert_called_once_with(
            apploop.sslctx_srv.wrap_socket, server_side=True
        )
        mock_getpeer.assert_called_once_with(apploop.sock)

    def test_action_withpeer(self, mocker):
        mock_getpeer = mocker.patch.object(
            message.StartTLSReply, '_getpeer', return_value='common'
        )
        apploop = mocker.Mock()
        obj = message.StartTLSReply()

        obj.action(apploop)

        apploop.display.assert_has_calls([
            mocker.call('Initiating TLS (server mode)'),
            mocker.call('TLS exchange succeeded; peer: common'),
        ])
        assert apploop.display.call_count == 2
        apploop.wrap.assert_called_once_with(
            apploop.sslctx_srv.wrap_socket, server_side=True
        )
        mock_getpeer.assert_called_once_with(apploop.sock)

    def test_reaction_failure(self, mocker):
        mock_getpeer = mocker.patch.object(
            message.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock(**{
            'wrap.side_effect': ExceptionForTest('some failure'),
        })
        obj = message.StartTLSReply()

        obj.reaction(apploop)

        apploop.display.assert_has_calls([
            mocker.call('Initiating TLS (client mode)'),
            mocker.call('TLS exchange failed: some failure'),
        ])
        assert apploop.display.call_count == 2
        apploop.wrap.assert_called_once_with(
            apploop.sslctx_cli.wrap_socket, server_side=False
        )
        assert not mock_getpeer.called

    def test_reaction_success(self, mocker):
        mock_getpeer = mocker.patch.object(
            message.StartTLSReply, '_getpeer', return_value='common'
        )
        apploop = mocker.Mock()
        obj = message.StartTLSReply()

        obj.reaction(apploop)

        apploop.display.assert_has_calls([
            mocker.call('Initiating TLS (client mode)'),
            mocker.call('TLS exchange succeeded; peer: common'),
        ])
        assert apploop.display.call_count == 2
        apploop.wrap.assert_called_once_with(
            apploop.sslctx_cli.wrap_socket, server_side=False
        )
        mock_getpeer.assert_called_once_with(apploop.sock)


class TestPingRequest(object):
    def test_reaction(self, mocker):
        mock_PingReply = mocker.patch.object(message, 'PingReply')
        apploop = mocker.Mock()
        obj = message.PingRequest(payload=b'payload')

        obj.reaction(apploop)

        mock_PingReply.assert_called_once_with(payload=b'payload')
        apploop.send_msg.assert_called_once_with(mock_PingReply.return_value)


class TestProtocol1(object):
    def test_error(self, mocker):
        flags = message.Message.carrier_flags.eset.flagset('error')
        mock_Message = mocker.patch.object(message, 'Message')
        mock_PingReply = mocker.patch.object(message, 'PingReply')
        mock_PingRequest = mocker.patch.object(message, 'PingRequest')

        result = message._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_Message.return_value
        mock_Message.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_PingReply.called
        assert not mock_PingRequest.called

    def test_reply(self, mocker):
        flags = message.Message.carrier_flags.eset.flagset('reply')
        mock_Message = mocker.patch.object(message, 'Message')
        mock_PingReply = mocker.patch.object(message, 'PingReply')
        mock_PingRequest = mocker.patch.object(message, 'PingRequest')

        result = message._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_PingReply.return_value
        assert not mock_Message.called
        mock_PingReply.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_PingRequest.called

    def test_request(self, mocker):
        flags = message.Message.carrier_flags.eset.flagset()
        mock_Message = mocker.patch.object(message, 'Message')
        mock_PingReply = mocker.patch.object(message, 'PingReply')
        mock_PingRequest = mocker.patch.object(message, 'PingRequest')

        result = message._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_PingRequest.return_value
        assert not mock_Message.called
        assert not mock_PingReply.called
        mock_PingRequest.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )


class TestProtocol2(object):
    def test_request(self, mocker):
        mock_StartTLSError = mocker.patch.object(message, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(message, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(message, 'StartTLSRequest')
        flags = message.Message.carrier_flags.eset.flagset()

        result = message._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSRequest.return_value
        assert not mock_StartTLSError.called
        assert not mock_StartTLSReply.called
        mock_StartTLSRequest.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )

    def test_error(self, mocker):
        mock_StartTLSError = mocker.patch.object(message, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(message, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(message, 'StartTLSRequest')
        flags = message.Message.carrier_flags.eset.flagset('error')

        result = message._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSError.return_value
        mock_StartTLSError.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_StartTLSReply.called
        assert not mock_StartTLSRequest.called

    def test_reply(self, mocker):
        mock_StartTLSError = mocker.patch.object(message, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(message, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(message, 'StartTLSRequest')
        flags = message.Message.carrier_flags.eset.flagset('reply')

        result = message._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSReply.return_value
        assert not mock_StartTLSError.called
        mock_StartTLSReply.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_StartTLSRequest.called


class TestSASLError(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            message.SASLError, '__init__', return_value=None
        )
        payload = u'This is a test message\u2026'.encode('utf-8')

        result = message.SASLError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.SASLError)
        mock_init.assert_called_once_with(
            u'This is a test message\u2026',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.SASLError(u'some message\u2026', a=1, b=2, c=3)

        assert result.msg == u'some message\u2026'
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        msg = u'This is a test message\u2026'
        obj = message.SASLError(msg)

        result = obj._encode()

        assert result == msg.encode('utf-8')

    def test_msg_str(self):
        msg = u'This is a test message\u2026'

        result = message.SASLError.msg.prepare('instance', msg)

        assert result == msg

    def test_msg_other(self):
        msg = 12345

        with pytest.raises(ValueError):
            message.SASLError.msg.prepare('instance', msg)


class TestRequestSASLMechanisms(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            message.RequestSASLMechanisms, '__init__', return_value=None
        )

        result = message.RequestSASLMechanisms._decode(255, a=1, b=2, c=3)

        assert isinstance(result, message.RequestSASLMechanisms)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        obj = message.RequestSASLMechanisms()

        result = obj._encode()

        assert result == b'\xff'


class TestSASLMechanisms(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            message.SASLMechanisms, '__init__', return_value=None
        )
        payload = b'\xffMECH1 MECH2  MECH3\tMECH4'

        result = message.SASLMechanisms._decode(
            255,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.SASLMechanisms)
        mock_init.assert_called_once_with(
            [b'MECH1', b'MECH2', b'MECH3', b'MECH4'],
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.SASLMechanisms(
            [b'MECH1', b'MECH2', b'MECH3'], a=1, b=2, c=3
        )

        assert result.mechs == [b'MECH1', b'MECH2', b'MECH3']
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        obj = message.SASLMechanisms([b'MECH1', b'MECH2', b'MECH3'])

        result = obj._encode()

        assert result == b'\xffMECH1 MECH2 MECH3'

    def test_mechs_base(self):
        mechs = [b'MECH1', b'MECH2', b'MECH3']

        result = message.SASLMechanisms.mechs.prepare('instance', mechs)

        assert result == mechs

    def test_mechs_upper(self):
        mechs = [b'mech1', b'mech2', b'mech3']

        result = message.SASLMechanisms.mechs.prepare('instance', mechs)

        assert result == [b'MECH1', b'MECH2', b'MECH3']

    def test_mechs_not_list(self):
        mechs = 12345

        with pytest.raises(ValueError):
            message.SASLMechanisms.mechs.prepare('instance', mechs)

    def test_mechs_not_bytes(self):
        mechs = [b'mech1', b'mech2', 12345]

        with pytest.raises(ValueError):
            message.SASLMechanisms.mechs.prepare('instance', mechs)


class TestSASLClientStep(object):
    def test_decode_nomech(self, mocker):
        mock_init = mocker.patch.object(
            message.SASLClientStep, '__init__', return_value=None
        )
        payload = b'\0Step Data'

        result = message.SASLClientStep._decode(
            0,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.SASLClientStep)
        mock_init.assert_called_once_with(
            None, b'Step Data',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_decode_withmech(self, mocker):
        mock_init = mocker.patch.object(
            message.SASLClientStep, '__init__', return_value=None
        )
        payload = b'\4MECHStep Data'

        result = message.SASLClientStep._decode(
            4,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.SASLClientStep)
        mock_init.assert_called_once_with(
            b'MECH', b'Step Data',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.SASLClientStep(a=1, b=2, c=3)

        assert result.mech is None
        assert result.data == b''
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.SASLClientStep(b'MECH', b'data', a=1, b=2, c=3)

        assert result.mech == b'MECH'
        assert result.data == b'data'
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode_nomech(self):
        obj = message.SASLClientStep(data=b'data')

        result = obj._encode()

        assert result == b'\x00data'

    def test_encode_withmech(self):
        obj = message.SASLClientStep(mech=b'MECH', data=b'data')

        result = obj._encode()

        assert result == b'\x04MECHdata'

    def test_mech_none(self):
        mech = None

        result = message.SASLClientStep.mech.prepare('instance', mech)

        assert result is None

    def test_mech_bytes(self):
        mech = b'MECH'

        result = message.SASLClientStep.mech.prepare('instance', mech)

        assert result == b'MECH'

    def test_mech_upper(self):
        mech = b'mech'

        result = message.SASLClientStep.mech.prepare('instance', mech)

        assert result == b'MECH'

    def test_mech_not_bytes(self):
        mech = 12345

        with pytest.raises(ValueError):
            message.SASLClientStep.mech.prepare('instance', mech)

    def test_data_none(self):
        data = None

        result = message.SASLClientStep.data.prepare('instance', data)

        assert result == b''

    def test_data_bytes(self):
        data = b'data'

        result = message.SASLClientStep.data.prepare('instance', data)

        assert result == b'data'

    def test_data_not_bytes(self):
        data = 12345

        with pytest.raises(ValueError):
            message.SASLClientStep.data.prepare('instance', data)


class TestProtocol3(object):
    def test_error(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset('error')
        payload = b'Some error message'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLError.return_value
        mock_SASLError.assert_called_once_with(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert not mock_RequestSASLMechanisms.called
        assert not mock_SASLMechanisms.called
        assert not mock_SASLClientStep.called
        assert not mock_SASLServerStep.called

    def test_mechanism_request(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset()
        payload = b'\xff'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_RequestSASLMechanisms.return_value
        assert not mock_SASLError.called
        mock_RequestSASLMechanisms.assert_called_once_with(
            255,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert not mock_SASLMechanisms.called
        assert not mock_SASLClientStep.called
        assert not mock_SASLServerStep.called

    def test_mechanism_response(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\xffmech1 mech2 mech3'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLMechanisms.return_value
        assert not mock_SASLError.called
        assert not mock_RequestSASLMechanisms.called
        mock_SASLMechanisms.assert_called_once_with(
            255,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert not mock_SASLClientStep.called
        assert not mock_SASLServerStep.called

    def test_client_step(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset()
        payload = b'\x04MECHdata'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLClientStep.return_value
        assert not mock_SASLError.called
        assert not mock_RequestSASLMechanisms.called
        assert not mock_SASLMechanisms.called
        mock_SASLClientStep.assert_called_once_with(
            4,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert not mock_SASLServerStep.called

    def test_client_step_nomech(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset()
        payload = b'\x00data'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLClientStep.return_value
        assert not mock_SASLError.called
        assert not mock_RequestSASLMechanisms.called
        assert not mock_SASLMechanisms.called
        mock_SASLClientStep.assert_called_once_with(
            0,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert not mock_SASLServerStep.called

    def test_server_step(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\x04MECHdata'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLServerStep.return_value
        assert not mock_SASLError.called
        assert not mock_RequestSASLMechanisms.called
        assert not mock_SASLMechanisms.called
        assert not mock_SASLClientStep.called
        mock_SASLServerStep.assert_called_once_with(
            4,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_server_step_nomech(self, mocker):
        mock_SASLError = mocker.patch.object(message.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            message.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            message.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            message.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            message.SASLServerStep, '_decode'
        )
        flags = message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\x00data'

        result = message._protocol3(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert result == mock_SASLServerStep.return_value
        assert not mock_SASLError.called
        assert not mock_RequestSASLMechanisms.called
        assert not mock_SASLMechanisms.called
        assert not mock_SASLClientStep.called
        mock_SASLServerStep.assert_called_once_with(
            0,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
