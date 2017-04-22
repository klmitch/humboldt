import pytest

from hum_proto.protocols import sasl


class TestSASLError(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            sasl.SASLError, '__init__', return_value=None
        )
        payload = u'This is a test message\u2026'.encode('utf-8')

        result = sasl.SASLError._decode(
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, sasl.SASLError)
        mock_init.assert_called_once_with(
            u'This is a test message\u2026',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init(self, mocker):
        mock_init = mocker.patch.object(
            sasl.message.Message, '__init__', return_value=None
        )

        result = sasl.SASLError(u'some message\u2026', a=1, b=2, c=3)

        assert result.msg == u'some message\u2026'
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        msg = u'This is a test message\u2026'
        obj = sasl.SASLError(msg)

        result = obj._encode()

        assert result == msg.encode('utf-8')

    def test_msg_str(self):
        msg = u'This is a test message\u2026'

        result = sasl.SASLError.msg.prepare('instance', msg)

        assert result == msg

    def test_msg_other(self):
        msg = 12345

        with pytest.raises(ValueError):
            sasl.SASLError.msg.prepare('instance', msg)


class TestRequestSASLMechanisms(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            sasl.RequestSASLMechanisms, '__init__', return_value=None
        )

        result = sasl.RequestSASLMechanisms._decode(255, a=1, b=2, c=3)

        assert isinstance(result, sasl.RequestSASLMechanisms)
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        obj = sasl.RequestSASLMechanisms()

        result = obj._encode()

        assert result == b'\xff'


class TestSASLMechanisms(object):
    def test_decode(self, mocker):
        mock_init = mocker.patch.object(
            sasl.SASLMechanisms, '__init__', return_value=None
        )
        payload = b'\xffMECH1 MECH2  MECH3\tMECH4'

        result = sasl.SASLMechanisms._decode(
            255,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, sasl.SASLMechanisms)
        mock_init.assert_called_once_with(
            [b'MECH1', b'MECH2', b'MECH3', b'MECH4'],
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init(self, mocker):
        mock_init = mocker.patch.object(
            sasl.message.Message, '__init__', return_value=None
        )

        result = sasl.SASLMechanisms(
            [b'MECH1', b'MECH2', b'MECH3'], a=1, b=2, c=3
        )

        assert result.mechs == [b'MECH1', b'MECH2', b'MECH3']
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode(self):
        obj = sasl.SASLMechanisms([b'MECH1', b'MECH2', b'MECH3'])

        result = obj._encode()

        assert result == b'\xffMECH1 MECH2 MECH3'

    def test_mechs_base(self):
        mechs = [b'MECH1', b'MECH2', b'MECH3']

        result = sasl.SASLMechanisms.mechs.prepare('instance', mechs)

        assert result == mechs

    def test_mechs_upper(self):
        mechs = [b'mech1', b'mech2', b'mech3']

        result = sasl.SASLMechanisms.mechs.prepare('instance', mechs)

        assert result == [b'MECH1', b'MECH2', b'MECH3']

    def test_mechs_not_list(self):
        mechs = 12345

        with pytest.raises(ValueError):
            sasl.SASLMechanisms.mechs.prepare('instance', mechs)

    def test_mechs_not_bytes(self):
        mechs = [b'mech1', b'mech2', 12345]

        with pytest.raises(ValueError):
            sasl.SASLMechanisms.mechs.prepare('instance', mechs)


class TestSASLClientStep(object):
    def test_decode_nomech(self, mocker):
        mock_init = mocker.patch.object(
            sasl.SASLClientStep, '__init__', return_value=None
        )
        payload = b'\0Step Data'

        result = sasl.SASLClientStep._decode(
            0,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, sasl.SASLClientStep)
        mock_init.assert_called_once_with(
            None, b'Step Data',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_decode_withmech(self, mocker):
        mock_init = mocker.patch.object(
            sasl.SASLClientStep, '__init__', return_value=None
        )
        payload = b'\4MECHStep Data'

        result = sasl.SASLClientStep._decode(
            4,
            payload=payload,
            a=1, b=2, c=3,
        )

        assert isinstance(result, sasl.SASLClientStep)
        mock_init.assert_called_once_with(
            b'MECH', b'Step Data',
            payload=payload,
            a=1, b=2, c=3,
        )

    def test_init_base(self, mocker):
        mock_init = mocker.patch.object(
            sasl.message.Message, '__init__', return_value=None
        )

        result = sasl.SASLClientStep(a=1, b=2, c=3)

        assert result.mech is None
        assert result.data == b''
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_init_alt(self, mocker):
        mock_init = mocker.patch.object(
            sasl.message.Message, '__init__', return_value=None
        )

        result = sasl.SASLClientStep(b'MECH', b'data', a=1, b=2, c=3)

        assert result.mech == b'MECH'
        assert result.data == b'data'
        mock_init.assert_called_once_with(a=1, b=2, c=3)

    def test_encode_nomech(self):
        obj = sasl.SASLClientStep(data=b'data')

        result = obj._encode()

        assert result == b'\x00data'

    def test_encode_withmech(self):
        obj = sasl.SASLClientStep(mech=b'MECH', data=b'data')

        result = obj._encode()

        assert result == b'\x04MECHdata'

    def test_mech_none(self):
        mech = None

        result = sasl.SASLClientStep.mech.prepare('instance', mech)

        assert result is None

    def test_mech_bytes(self):
        mech = b'MECH'

        result = sasl.SASLClientStep.mech.prepare('instance', mech)

        assert result == b'MECH'

    def test_mech_upper(self):
        mech = b'mech'

        result = sasl.SASLClientStep.mech.prepare('instance', mech)

        assert result == b'MECH'

    def test_mech_not_bytes(self):
        mech = 12345

        with pytest.raises(ValueError):
            sasl.SASLClientStep.mech.prepare('instance', mech)

    def test_data_none(self):
        data = None

        result = sasl.SASLClientStep.data.prepare('instance', data)

        assert result == b''

    def test_data_bytes(self):
        data = b'data'

        result = sasl.SASLClientStep.data.prepare('instance', data)

        assert result == b'data'

    def test_data_not_bytes(self):
        data = 12345

        with pytest.raises(ValueError):
            sasl.SASLClientStep.data.prepare('instance', data)


class TestProtocol3(object):
    def test_error(self, mocker):
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset('error')
        payload = b'Some error message'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset()
        payload = b'\xff'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\xffmech1 mech2 mech3'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset()
        payload = b'\x04MECHdata'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset()
        payload = b'\x00data'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\x04MECHdata'

        result = sasl._protocol3(
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
        mock_SASLError = mocker.patch.object(sasl.SASLError, '_decode')
        mock_RequestSASLMechanisms = mocker.patch.object(
            sasl.RequestSASLMechanisms, '_decode'
        )
        mock_SASLMechanisms = mocker.patch.object(
            sasl.SASLMechanisms, '_decode'
        )
        mock_SASLClientStep = mocker.patch.object(
            sasl.SASLClientStep, '_decode'
        )
        mock_SASLServerStep = mocker.patch.object(
            sasl.SASLServerStep, '_decode'
        )
        flags = sasl.message.Message.carrier_flags.eset.flagset('reply')
        payload = b'\x00data'

        result = sasl._protocol3(
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
