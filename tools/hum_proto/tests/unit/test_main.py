from hum_proto import main


class TestMain(object):
    def test_base(self, mocker):
        mock_get_ctx = mocker.patch.object(main.ssl_utils, 'get_ctx')
        sslctx = mock_get_ctx.return_value
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value

        main.main('endpoint', 'certfile', 'keyfile')

        mock_get_ctx.assert_called_once_with('certfile', 'keyfile')
        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock, sslctx)
        app.run.assert_called_once_with()
        app.sock.close.assert_called_once_with()

    def test_no_endpoint(self, mocker):
        mock_get_ctx = mocker.patch.object(main.ssl_utils, 'get_ctx')
        sslctx = mock_get_ctx.return_value
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value

        main.main(None, 'certfile', 'keyfile')

        mock_get_ctx.assert_called_once_with('certfile', 'keyfile')
        assert not mock_connect.called
        mock_ApplicationLoop.assert_called_once_with(None, sslctx)
        app.run.assert_called_once_with()
        app.sock.close.assert_called_once_with()

    def test_no_close(self, mocker):
        mock_get_ctx = mocker.patch.object(main.ssl_utils, 'get_ctx')
        sslctx = mock_get_ctx.return_value
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value
        app.sock = None

        main.main('endpoint', 'certfile', 'keyfile')

        mock_get_ctx.assert_called_once_with('certfile', 'keyfile')
        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock, sslctx)
        app.run.assert_called_once_with()
        assert app.sock is None
