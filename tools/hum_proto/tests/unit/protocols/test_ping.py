from hum_proto.protocols import ping


class TestPingRequest(object):
    def test_reaction(self, mocker):
        mock_PingReply = mocker.patch.object(ping, 'PingReply')
        apploop = mocker.Mock()
        obj = ping.PingRequest(payload=b'payload')

        obj.reaction(apploop)

        mock_PingReply.assert_called_once_with(payload=b'payload')
        apploop.send_msg.assert_called_once_with(mock_PingReply.return_value)


class TestProtocol1(object):
    def test_error(self, mocker):
        flags = ping.message.Message.carrier_flags.eset.flagset('error')
        mock_Message = mocker.patch.object(ping.message, 'Message')
        mock_PingReply = mocker.patch.object(ping, 'PingReply')
        mock_PingRequest = mocker.patch.object(ping, 'PingRequest')

        result = ping._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_Message.return_value
        mock_Message.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_PingReply.called
        assert not mock_PingRequest.called

    def test_reply(self, mocker):
        flags = ping.message.Message.carrier_flags.eset.flagset('reply')
        mock_Message = mocker.patch.object(ping.message, 'Message')
        mock_PingReply = mocker.patch.object(ping, 'PingReply')
        mock_PingRequest = mocker.patch.object(ping, 'PingRequest')

        result = ping._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_PingReply.return_value
        assert not mock_Message.called
        mock_PingReply.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_PingRequest.called

    def test_request(self, mocker):
        flags = ping.message.Message.carrier_flags.eset.flagset()
        mock_Message = mocker.patch.object(ping.message, 'Message')
        mock_PingReply = mocker.patch.object(ping, 'PingReply')
        mock_PingRequest = mocker.patch.object(ping, 'PingRequest')

        result = ping._protocol1(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_PingRequest.return_value
        assert not mock_Message.called
        assert not mock_PingReply.called
        mock_PingRequest.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
