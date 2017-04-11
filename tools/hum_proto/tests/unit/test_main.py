from hum_proto import main


class TestMain(object):
    def test_base(self, mocker):
        mock_get_ctx = mocker.patch.object(
            main.ssl_utils, 'get_ctx', side_effect=['cli', 'srv']
        )
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value

        main.main('endpoint', 'certfile', 'keyfile')

        mock_get_ctx.assert_has_calls([
            mocker.call('certfile', 'keyfile'),
            mocker.call('certfile', 'keyfile', False),
        ])
        assert mock_get_ctx.call_count == 2
        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock, 'cli', 'srv')
        app.run.assert_called_once_with()
        app.sock.close.assert_called_once_with()

    def test_no_endpoint(self, mocker):
        mock_get_ctx = mocker.patch.object(
            main.ssl_utils, 'get_ctx', side_effect=['cli', 'srv']
        )
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value

        main.main(None, 'certfile', 'keyfile')

        mock_get_ctx.assert_has_calls([
            mocker.call('certfile', 'keyfile'),
            mocker.call('certfile', 'keyfile', False),
        ])
        assert mock_get_ctx.call_count == 2
        assert not mock_connect.called
        mock_ApplicationLoop.assert_called_once_with(None, 'cli', 'srv')
        app.run.assert_called_once_with()
        app.sock.close.assert_called_once_with()

    def test_no_close(self, mocker):
        mock_get_ctx = mocker.patch.object(
            main.ssl_utils, 'get_ctx', side_effect=['cli', 'srv']
        )
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value
        app.sock = None

        main.main('endpoint', 'certfile', 'keyfile')

        mock_get_ctx.assert_has_calls([
            mocker.call('certfile', 'keyfile'),
            mocker.call('certfile', 'keyfile', False),
        ])
        assert mock_get_ctx.call_count == 2
        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock, 'cli', 'srv')
        app.run.assert_called_once_with()
        assert app.sock is None
