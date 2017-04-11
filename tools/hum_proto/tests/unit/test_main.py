from hum_proto import main


class TestMain(object):
    def test_base(self, mocker):
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value

        main.main('endpoint')

        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock)
        app.run.assert_called_once_with()
        app.sock.close.assert_called_once_with()

    def test_no_close(self, mocker):
        mock_connect = mocker.patch.object(main.apploop, 'connect')
        sock = mock_connect.return_value
        mock_ApplicationLoop = mocker.patch.object(
            main.apploop, 'ApplicationLoop'
        )
        app = mock_ApplicationLoop.return_value
        app.sock = None

        main.main('endpoint')

        mock_connect.assert_called_once_with('endpoint')
        mock_ApplicationLoop.assert_called_once_with(sock)
        app.run.assert_called_once_with()
        assert app.sock is None
