import uuid

import pytest

from hum_proto import message


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
    def test_register_base(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)

        decorator = message.Message.register(5)

        assert callable(decorator)
        assert message.Message._protocols == {}

        cls = mocker.Mock()

        result = decorator(cls)

        assert result is cls
        assert cls.PROTOCOL == 5
        assert message.Message._protocols == {5: cls}

    def test_register_low_proto(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)

        with pytest.raises(TypeError):
            message.Message.register(-1)
        assert message.Message._protocols == {}

    def test_register_high_proto(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)

        with pytest.raises(TypeError):
            message.Message.register(256)
        assert message.Message._protocols == {}

    def test_register_duplicate_proto(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        message.Message._protocols[5] = 'proto'

        with pytest.raises(TypeError):
            message.Message.register(5)
        assert message.Message._protocols == {5: 'proto'}

    def test_decode_header_only(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

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

    def test_decode_vers_flags(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\70\3\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

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

    def test_decode_with_payload(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a test',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

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

    def test_decode_header_only_short(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

        assert result is None
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        assert not mock_init.called

    def test_decode_with_payload_short(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a t',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

        assert result is None
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        assert not mock_init.called

    def test_decode_header_only_registered(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        proto = mocker.Mock()
        message.Message._protocols[0] = proto
        mock_recvall = mocker.patch.object(
            message, '_recvall', return_value=b'\0\0\0\4'
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

        assert result == proto._decode.return_value
        mock_recvall.assert_called_once_with(
            'sock', message.Message._carrier.size
        )
        assert not mock_init.called
        proto._decode.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'',
            _bytes=b'\0\0\0\4',
        )

    def test_decode_with_payload_registered(self, mocker):
        mocker.patch.dict(message.Message._protocols, clear=True)
        proto = mocker.Mock()
        message.Message._protocols[0] = proto
        mock_recvall = mocker.patch.object(
            message, '_recvall', side_effect=[
                b'\0\0\0\22',
                b'this is a test',
            ],
        )
        mock_init = mocker.patch.object(
            message.Message, '__init__', return_value=None
        )

        result = message.Message.decode('sock')

        assert result == proto._decode.return_value
        mock_recvall.assert_has_calls([
            mocker.call('sock', message.Message._carrier.size),
            mocker.call('sock', 14),
        ])
        assert mock_recvall.call_count == 2
        assert not mock_init.called
        proto._decode.assert_called_once_with(
            carrier_version=0,
            carrier_flags=mocker.ANY,
            protocol=0,
            payload=b'this is a test',
            _bytes=b'\0\0\0\22this is a test',
        )

    def test_init(self):
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

    def test_encode(self, mocker):
        mocker.patch.object(message.Message, 'bytes', b'1234')
        sock = mocker.Mock()
        obj = message.Message()

        obj.encode(sock)

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
    def test_decode_base(self, mocker):
        mock_init = mocker.patch.object(
            message.ConnectionState, '__init__', return_value=None
        )
        flags = message.Message.carrier_flags.eset.flagset('reply')
        node_id = uuid.uuid4()
        payload = b'\200\377\0\0' + node_id.bytes

        result = message.ConnectionState._decode(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.ConnectionState)
        mock_init.assert_called_once_with(
            mocker.ANY, 255, node_id,
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )
        assert int(mock_init.call_args[0][0]) == 0x80

    def test_decode_other(self, mocker):
        mock_init = mocker.patch.object(
            message.ConnectionState, '__init__', return_value=None
        )
        flags = message.Message.carrier_flags.eset.flagset('error')
        node_id = uuid.uuid4()
        payload = b'\200\377\0\0' + node_id.bytes

        result = message.ConnectionState._decode(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, message.ConnectionState)
        mock_init.assert_called_once_with(
            carrier_flags=flags,
            payload=payload,
            a=1, b=2, c=3,
        )

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

    def test_encode_reply(self):
        node_id = uuid.uuid4()
        obj = message.ConnectionState(
            'client', 'ERROR', node_id, carrier_flags='reply'
        )

        result = obj._encode()

        assert result == b'\200\377\0\0' + node_id.bytes

    def test_encode_other(self):
        node_id = uuid.uuid4()
        obj = message.ConnectionState(
            'client', 'ERROR', node_id
        )

        result = obj._encode()

        assert result == b''

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
