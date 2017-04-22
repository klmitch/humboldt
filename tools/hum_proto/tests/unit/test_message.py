import pytest

from hum_proto import message


class ExceptionForTest(Exception):
    pass


class TestFlagger(object):
    def test_int(self):
        result = message.flagger('1234')

        assert result == 1234

    def test_str(self):
        result = message.flagger('1, 2, 3')

        assert result == ['1', '2', '3']


class TestEnumer(object):
    def test_int(self):
        result = message.enumer('1234')

        assert result == 1234

    def test_str(self):
        result = message.enumer('other')

        assert result == 'other'


class TestByter(object):
    def test_base(self):
        result = message.byter('this is a test')

        assert result == b'this is a test'

    def test_escapes(self):
        result = message.byter('\\\'\\"\\a\\b\\f\\n\\r\\t\\v\\xff'
                               '\\1\\12\\123\\1234\\\\\\o')

        assert result == b'\'"\a\b\f\n\r\t\v\xff\x01\x0a\x53\x534\\\\o'

    def test_badhex(self):
        with pytest.raises(ValueError):
            message.byter('\\x')
        with pytest.raises(ValueError):
            message.byter('\\x1')
        with pytest.raises(ValueError):
            message.byter('\\x1z')

    def test_octoverflow(self):
        result = message.byter('\\377\\400')

        assert result == b'\377\40\60'


class TestSplitter(object):
    def test_base(self):
        result = message.splitter('1, 2, 3')

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
