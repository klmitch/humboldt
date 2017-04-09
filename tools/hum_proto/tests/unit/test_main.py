import socket

import pytest

from hum_proto import main


class ExceptionForTest(Exception):
    pass


class Exception2ForTest(Exception):
    pass


class TestConnect(object):
    def test_local(self, mocker):
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(main.socket, 'getaddrinfo')

        result = main.connect('foo/bar')

        assert result == sock
        mock_socket.assert_called_once_with(
            socket.AF_UNIX, socket.SOCK_STREAM, 0
        )
        sock.connect.assert_called_once_with('foo/bar')
        assert not mock_getaddrinfo.called

    def test_host(self, mocker):
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = main.connect('host.name')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            'host.name', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_host_with_port(self, mocker):
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = main.connect('host.name:1234')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            'host.name', '1234', socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_ipv6(self, mocker):
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = main.connect('[::1]')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            '::1', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_ipv6_with_port(self, mocker):
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = main.connect('[::1]:1234')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            '::1', '1234', socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_all_entries(self, mocker):
        def fake_connect(sockaddr):
            if isinstance(sockaddr, Exception):
                raise sockaddr
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        sock.connect.side_effect = fake_connect
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family1', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family2', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family3', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family4', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = main.connect('host.name')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            'host.name', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_has_calls([
            mocker.call('family1', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family2', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family3', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family4', 'socktype', 'proto'),
            mocker.call().connect('sockaddr'),
        ])
        assert mock_socket.call_count == 4
        assert sock.connect.call_count == 4

    def test_reraise(self, mocker):
        def fake_connect(sockaddr):
            if isinstance(sockaddr, Exception):
                raise sockaddr
        mock_socket = mocker.patch.object(main.socket, 'socket')
        sock = mock_socket.return_value
        sock.connect.side_effect = fake_connect
        mock_getaddrinfo = mocker.patch.object(
            main.socket, 'getaddrinfo',
            return_value=[
                ('family1', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family2', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family3', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family4', 'socktype', 'proto', 'canon', Exception2ForTest()),
            ],
        )

        with pytest.raises(Exception2ForTest):
            main.connect('host.name')
        mock_getaddrinfo.assert_called_once_with(
            'host.name', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_has_calls([
            mocker.call('family1', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family2', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family3', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
            mocker.call('family4', 'socktype', 'proto'),
            mocker.call().connect(mocker.ANY),
        ])
        assert mock_socket.call_count == 4
        assert sock.connect.call_count == 4


class TestMain(object):
    def test_base(self, mocker):
        mock_connect = mocker.patch.object(main, 'connect')
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
        mock_connect = mocker.patch.object(main, 'connect')
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
