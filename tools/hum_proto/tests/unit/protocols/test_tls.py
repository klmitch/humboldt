from hum_proto.protocols import tls


class ExceptionForTest(Exception):
    pass


class TestStartTLSReply(object):
    def test_getpeer_nopeer(self, mocker):
        sock = mocker.Mock(**{
            'getpeercert.return_value': None,
        })
        obj = tls.StartTLSReply()

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
        obj = tls.StartTLSReply()

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
        obj = tls.StartTLSReply()

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
            tls.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock(**{
            'wrap.side_effect': ExceptionForTest('some failure'),
        })
        obj = tls.StartTLSReply()

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
            tls.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock()
        obj = tls.StartTLSReply()

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
            tls.StartTLSReply, '_getpeer', return_value='common'
        )
        apploop = mocker.Mock()
        obj = tls.StartTLSReply()

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
            tls.StartTLSReply, '_getpeer', return_value=None
        )
        apploop = mocker.Mock(**{
            'wrap.side_effect': ExceptionForTest('some failure'),
        })
        obj = tls.StartTLSReply()

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
            tls.StartTLSReply, '_getpeer', return_value='common'
        )
        apploop = mocker.Mock()
        obj = tls.StartTLSReply()

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


class TestProtocol2(object):
    def test_request(self, mocker):
        mock_StartTLSError = mocker.patch.object(tls, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(tls, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(tls, 'StartTLSRequest')
        flags = tls.message.Message.carrier_flags.eset.flagset()

        result = tls._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSRequest.return_value
        assert not mock_StartTLSError.called
        assert not mock_StartTLSReply.called
        mock_StartTLSRequest.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )

    def test_error(self, mocker):
        mock_StartTLSError = mocker.patch.object(tls, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(tls, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(tls, 'StartTLSRequest')
        flags = tls.message.Message.carrier_flags.eset.flagset('error')

        result = tls._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSError.return_value
        mock_StartTLSError.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_StartTLSReply.called
        assert not mock_StartTLSRequest.called

    def test_reply(self, mocker):
        mock_StartTLSError = mocker.patch.object(tls, 'StartTLSError')
        mock_StartTLSReply = mocker.patch.object(tls, 'StartTLSReply')
        mock_StartTLSRequest = mocker.patch.object(tls, 'StartTLSRequest')
        flags = tls.message.Message.carrier_flags.eset.flagset('reply')

        result = tls._protocol2(carrier_flags=flags, a=1, b=2, c=3)

        assert result == mock_StartTLSReply.return_value
        assert not mock_StartTLSError.called
        mock_StartTLSReply.assert_called_once_with(
            carrier_flags=flags, a=1, b=2, c=3
        )
        assert not mock_StartTLSRequest.called
