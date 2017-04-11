import socket

from prompt_toolkit import buffer
import pytest

from hum_proto import apploop
from hum_proto import message


class ExceptionForTest(Exception):
    pass


class Exception2ForTest(Exception):
    pass


class TestConnect(object):
    def test_local(self, mocker):
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(apploop.socket, 'getaddrinfo')

        result = apploop.connect('foo/bar')

        assert result == sock
        mock_socket.assert_called_once_with(
            socket.AF_UNIX, socket.SOCK_STREAM, 0
        )
        sock.connect.assert_called_once_with('foo/bar')
        assert not mock_getaddrinfo.called

    def test_host(self, mocker):
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = apploop.connect('host.name')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            'host.name', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_host_with_port(self, mocker):
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = apploop.connect('host.name:1234')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            'host.name', '1234', socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_ipv6(self, mocker):
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = apploop.connect('[::1]')

        assert result == sock
        mock_getaddrinfo.assert_called_once_with(
            '::1', 7300, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        mock_socket.assert_called_once_with('family', 'socktype', 'proto')
        sock.connect.assert_called_once_with('sockaddr')

    def test_ipv6_with_port(self, mocker):
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = apploop.connect('[::1]:1234')

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
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        sock.connect.side_effect = fake_connect
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family1', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family2', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family3', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family4', 'socktype', 'proto', 'canon', 'sockaddr'),
            ],
        )

        result = apploop.connect('host.name')

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
        mock_socket = mocker.patch.object(apploop.socket, 'socket')
        sock = mock_socket.return_value
        sock.connect.side_effect = fake_connect
        mock_getaddrinfo = mocker.patch.object(
            apploop.socket, 'getaddrinfo',
            return_value=[
                ('family1', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family2', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family3', 'socktype', 'proto', 'canon', ExceptionForTest()),
                ('family4', 'socktype', 'proto', 'canon', Exception2ForTest()),
            ],
        )

        with pytest.raises(Exception2ForTest):
            apploop.connect('host.name')
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


class TestCommand(object):
    def test_bare(self):
        @apploop.command
        def test_func():
            pass

        assert test_func._command_name == 'test_func'
        assert test_func._command_aliases == []

    def test_empty(self):
        @apploop.command()
        def test_func():
            pass

        assert test_func._command_name == 'test_func'
        assert test_func._command_aliases == []

    def test_empty_aliases(self):
        @apploop.command(aliases=['alias1', 'alias2'])
        def test_func():
            pass

        assert test_func._command_name == 'test_func'
        assert test_func._command_aliases == ['alias1', 'alias2']

    def test_named(self):
        @apploop.command('command')
        def test_func():
            pass

        assert test_func._command_name == 'command'
        assert test_func._command_aliases == []

    def test_named_aliases(self):
        @apploop.command('command', aliases=['alias1', 'alias2'])
        def test_func():
            pass

        assert test_func._command_name == 'command'
        assert test_func._command_aliases == ['alias1', 'alias2']


class TestApplicationLoopMeta(object):
    def test_init(self, mocker):
        namespace = {
            'a': mocker.Mock(spec=[]),
            'b': 1,
            'c': mocker.Mock(_command_name='c1', _command_aliases=[]),
            'd': mocker.Mock(
                _command_name='c2', _command_aliases=['a1', 'a2']
            ),
        }

        result = apploop.ApplicationLoopMeta('TestClass', (object,), namespace)

        assert result._commands == {
            'c1': namespace['c'],
            'c2': namespace['d'],
            'a1': namespace['d'],
            'a2': namespace['d'],
        }


class TestApplicationLoop(object):
    def test_init(self, mocker):
        result = apploop.ApplicationLoop('sock')

        assert result.sock == 'sock'
        assert result._cli is None
        assert isinstance(result.display_buf, buffer.Buffer)
        assert isinstance(result.command_buf, buffer.Buffer)
        assert isinstance(
            result.command_buf.accept_action, buffer.AcceptAction
        )
        assert result.command_buf.accept_action.handler == result.execute

    def test_close_internal_closed(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop(None)

        obj._close()

        assert not mock_display.called
        assert not mock_cli.eventloop.remove_reader.called

    def test_close_internal_open(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        sock = mocker.Mock()
        obj = apploop.ApplicationLoop(sock)

        obj._close()

        assert obj.sock is None
        mock_display.assert_called_once_with('Connection closed')
        mock_cli.eventloop.remove_reader.assert_called_once_with(sock)
        sock.close.assert_called_once_with()

    def test_recv_close(self, mocker):
        mock_recv = mocker.patch.object(
            apploop.message.Message, 'recv', return_value=None
        )
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj._recv()

        mock_recv.assert_called_once_with('sock')
        mock_close.assert_called_once_with()
        assert not mock_display.called
        mock_cli.invalidate.assert_called_once_with()

    def test_recv_msg_noaction(self, mocker):
        msg = mocker.Mock(
            __repr__=mocker.Mock(return_value='"a message"'),
            reaction=None,
        )
        mock_recv = mocker.patch.object(
            apploop.message.Message, 'recv', return_value=msg
        )
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj._recv()

        mock_recv.assert_called_once_with('sock')
        assert not mock_close.called
        mock_display.assert_called_once_with('S: "a message"')
        mock_cli.invalidate.assert_called_once_with()

    def test_recv_msg_withaction(self, mocker):
        msg = mocker.Mock(__repr__=mocker.Mock(return_value='"a message"'))
        mock_recv = mocker.patch.object(
            apploop.message.Message, 'recv', return_value=msg
        )
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj._recv()

        mock_recv.assert_called_once_with('sock')
        assert not mock_close.called
        mock_display.assert_called_once_with('S: "a message"')
        mock_cli.invalidate.assert_called_once_with()
        msg.reaction.assert_called_once_with(obj)

    def test_display(self, mocker):
        mocker.patch.object(apploop.buffer, 'Buffer')
        obj = apploop.ApplicationLoop('sock')

        obj.display('text')

        obj.display_buf.insert_text.assert_called_once_with('text\n')

    def test_execute_no_text(self, mocker):
        mocker.patch.dict(apploop.ApplicationLoop._commands, clear=True)
        mocker.patch.object(apploop.buffer, 'Buffer')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        doc = mocker.Mock(text='')
        obj = apploop.ApplicationLoop('sock')

        obj.execute('cli', doc)

        assert not obj.command_buf.reset.called
        assert not mock_display.called

    def test_execute_not_found(self, mocker):
        mocker.patch.dict(apploop.ApplicationLoop._commands, clear=True)
        mocker.patch.object(apploop.buffer, 'Buffer')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        doc = mocker.Mock(text='this is "a test"')
        obj = apploop.ApplicationLoop('sock')

        obj.execute('cli', doc)

        obj.command_buf.reset.assert_called_once_with(append_to_history=True)
        mock_display.assert_called_once_with('ERROR: Unknown command "this"')

    def test_execute_found(self, mocker):
        command = mocker.Mock()
        mocker.patch.dict(
            apploop.ApplicationLoop._commands, clear=True, this=command,
        )
        mocker.patch.object(apploop.buffer, 'Buffer')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        doc = mocker.Mock(text='this is "a test"')
        obj = apploop.ApplicationLoop('sock')

        obj.execute('cli', doc)

        obj.command_buf.reset.assert_called_once_with(append_to_history=True)
        assert not mock_display.called
        command.assert_called_once_with(obj, ['is', 'a test'])

    def test_exit(self, mocker):
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj.exit('args')

        mock_close.assert_called_once_with()
        mock_cli.set_return_value.assert_called_once_with(None)

    def test_close(self, mocker):
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        obj = apploop.ApplicationLoop('sock')

        obj.close('args')

        mock_close.assert_called_once_with()

    def test_connect_too_few_args(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_connect = mocker.patch.object(apploop, 'connect')
        mock_setsock = mocker.patch.object(apploop.ApplicationLoop, 'setsock')
        obj = apploop.ApplicationLoop('sock')

        obj.connect([])

        mock_display.assert_called_once_with(
            'ERROR: too few arguments for connect'
        )
        assert not mock_connect.called
        assert not mock_setsock.called

    def test_connect_too_many_args(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_connect = mocker.patch.object(apploop, 'connect')
        mock_setsock = mocker.patch.object(apploop.ApplicationLoop, 'setsock')
        obj = apploop.ApplicationLoop('sock')

        obj.connect(['host', 'host2'])

        mock_display.assert_called_once_with(
            'ERROR: too many arguments for connect'
        )
        assert not mock_connect.called
        assert not mock_setsock.called

    def test_connect_failed(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_connect = mocker.patch.object(
            apploop, 'connect', side_effect=ExceptionForTest('failure')
        )
        mock_setsock = mocker.patch.object(apploop.ApplicationLoop, 'setsock')
        obj = apploop.ApplicationLoop('sock')

        obj.connect(['host'])

        mock_display.assert_called_once_with(
            'ERROR: Unable to connect to host: failure'
        )
        mock_connect.assert_called_once_with('host')
        assert not mock_setsock.called

    def test_connect_connected(self, mocker):
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        mock_connect = mocker.patch.object(apploop, 'connect')
        mock_setsock = mocker.patch.object(apploop.ApplicationLoop, 'setsock')
        obj = apploop.ApplicationLoop('sock')

        obj.connect(['host'])

        mock_display.assert_called_once_with('Connected to host')
        mock_connect.assert_called_once_with('host')
        mock_setsock.assert_called_once_with(mock_connect.return_value)

    def test_send_failure(self, mocker):
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret',
            side_effect=message.CommandError('some problem'),
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop('sock')

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        mock_display.assert_called_once_with(
            'ERROR: Failed to understand message to send: some problem'
        )

    def test_send_closed_noaction(self, mocker):
        msg = mocker.Mock(
            __repr__=mocker.Mock(return_value='"a message"'),
            action=None,
        )
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret', return_value=msg
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop(None)

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        mock_display.assert_called_once_with('ERROR: Connection is closed')
        assert not msg.send.called

    def test_send_closed_withaction(self, mocker):
        msg = mocker.Mock(__repr__=mocker.Mock(return_value='"a message"'))
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret', return_value=msg
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop(None)

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        mock_display.assert_called_once_with('ERROR: Connection is closed')
        assert not msg.send.called
        assert not msg.action.called

    def test_send_sent_noaction(self, mocker):
        msg = mocker.Mock(
            __repr__=mocker.Mock(return_value='"a message"'),
            action=None,
        )
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret', return_value=msg
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop('sock')

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        msg.send.assert_called_once_with('sock')
        mock_display.assert_called_once_with('C: "a message"')

    def test_send_sent_withaction(self, mocker):
        msg = mocker.Mock(__repr__=mocker.Mock(return_value='"a message"'))
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret', return_value=msg
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop('sock')

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        msg.send.assert_called_once_with('sock')
        msg.action.assert_called_once_with(obj)
        mock_display.assert_called_once_with('C: "a message"')

    def test_setsock_closed(self, mocker):
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop(None)

        obj.setsock('newsock')

        assert obj.sock == 'newsock'
        assert not mock_close.called
        mock_cli.eventloop.add_reader.assert_called_once_with(
            'newsock', obj._recv
        )

    def test_setsock_open(self, mocker):
        mock_close = mocker.patch.object(apploop.ApplicationLoop, '_close')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj.setsock('newsock')

        assert obj.sock == 'newsock'
        mock_close.assert_called_once_with()
        mock_cli.eventloop.add_reader.assert_called_once_with(
            'newsock', obj._recv
        )

    def test_wrap_closed(self, mocker):
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        wrapper = mocker.Mock()
        obj = apploop.ApplicationLoop(None)

        obj.wrap(wrapper)

        assert obj.sock is None
        assert not mock_cli.eventloop.remove_reader.called
        assert not wrapper.called
        assert not mock_cli.eventloop.add_reader.called
        assert not mock_display.called

    def test_wrap_open(self, mocker):
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        wrapper = mocker.Mock()
        obj = apploop.ApplicationLoop('sock')

        obj.wrap(wrapper)

        assert obj.sock == wrapper.return_value
        mock_cli.eventloop.remove_reader.assert_called_once_with('sock')
        wrapper.assert_called_once_with('sock')
        mock_cli.eventloop.add_reader.assert_called_once_with(
            wrapper.return_value, obj._recv
        )
        mock_display.assert_called_once_with('Socket wrapped')

    def test_wrap_open_message(self, mocker):
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        wrapper = mocker.Mock()
        obj = apploop.ApplicationLoop('sock')

        obj.wrap(wrapper, 'message')

        assert obj.sock == wrapper.return_value
        mock_cli.eventloop.remove_reader.assert_called_once_with('sock')
        wrapper.assert_called_once_with('sock')
        mock_cli.eventloop.add_reader.assert_called_once_with(
            wrapper.return_value, obj._recv
        )
        mock_display.assert_called_once_with('message')

    def test_run_no_sock(self, mocker):
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop(None)

        obj.run()

        assert not mock_cli.eventloop.add_reader.called
        mock_cli.run.assert_called_once_with()

    def test_run_with_sock(self, mocker):
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj.run()

        mock_cli.eventloop.add_reader.assert_called_once_with(
            'sock', obj._recv
        )
        mock_cli.run.assert_called_once_with()

    def test_cli_uncached(self, mocker):
        mocker.patch.object(
            apploop.controls, 'BufferControl',
            side_effect=lambda x: 'buffer-%s' % x
        )
        mocker.patch.object(
            apploop.dimension.LayoutDimension, 'exact',
            side_effect=lambda x: 'exact-%d' % x
        )
        mocker.patch.object(
            apploop.controls, 'FillControl',
            side_effect=lambda x: 'fill-%s' % x
        )
        mocker.patch.object(
            apploop.containers, 'Window',
            side_effect=lambda **kw: 'window(%s)' %
            ','.join('%s=%s' % (k, v) for k, v in
                     sorted(kw.items(), key=lambda x: x[0]))
        )
        mocker.patch.object(
            apploop.containers, 'HSplit',
            side_effect=lambda x: 'hsplit(%s)' % ','.join(x)
        )
        mock_Application = mocker.patch.object(
            apploop.application, 'Application'
        )
        mock_create_eventloop = mocker.patch.object(
            apploop.shortcuts, 'create_eventloop'
        )
        mock_CommandLineInterface = mocker.patch.object(
            apploop.interface, 'CommandLineInterface'
        )
        obj = apploop.ApplicationLoop('sock')

        result = obj.cli

        assert result == mock_CommandLineInterface.return_value
        assert obj._cli == mock_CommandLineInterface.return_value
        mock_Application.assert_called_once_with(
            layout='hsplit(window(content=buffer-display,wrap_lines=True),'
            'window(content=fill--,height=exact-1),'
            'window(content=buffer-command,height=exact-3,wrap_lines=True))',
            mouse_support=True,
            use_alternate_screen=True,
            buffers={
                'display': obj.display_buf,
                'command': obj.command_buf,
            },
            initial_focussed_buffer='command',
        )
        mock_create_eventloop.assert_called_once_with()
        mock_CommandLineInterface.assert_called_once_with(
            application=mock_Application.return_value,
            eventloop=mock_create_eventloop.return_value,
        )

    def test_cli_cached(self, mocker):
        mocker.patch.object(
            apploop.controls, 'BufferControl',
            side_effect=lambda x: 'buffer-%s' % x
        )
        mocker.patch.object(
            apploop.dimension.LayoutDimension, 'exact',
            side_effect=lambda x: 'exact-%d' % x
        )
        mocker.patch.object(
            apploop.controls, 'FillControl',
            side_effect=lambda x: 'fill-%s' % x
        )
        mocker.patch.object(
            apploop.containers, 'Window',
            side_effect=lambda **kw: 'window(%s)' %
            ','.join('%s=%s' % (k, v) for k, v in
                     sorted(kw.items(), key=lambda x: x[0]))
        )
        mocker.patch.object(
            apploop.containers, 'HSplit',
            side_effect=lambda x: 'hsplit(%s)' % ','.join(x)
        )
        mock_Application = mocker.patch.object(
            apploop.application, 'Application'
        )
        mock_create_eventloop = mocker.patch.object(
            apploop.shortcuts, 'create_eventloop'
        )
        mock_CommandLineInterface = mocker.patch.object(
            apploop.interface, 'CommandLineInterface'
        )
        obj = apploop.ApplicationLoop('sock')
        obj._cli = 'cached'

        result = obj.cli

        assert result == 'cached'
        assert obj._cli == 'cached'
        assert not mock_Application.called
        assert not mock_create_eventloop.called
        assert not mock_CommandLineInterface.called
