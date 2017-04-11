from prompt_toolkit import buffer

from hum_proto import apploop
from hum_proto import message
from hum_proto import qsock


class TestCommand(object):
    def test_bare(self):
        @apploop.command
        def test_func():
            pass

        assert test_func._command_name == 'test_func'

    def test_empty(self):
        @apploop.command()
        def test_func():
            pass

        assert test_func._command_name == 'test_func'

    def test_named(self):
        @apploop.command('command')
        def test_func():
            pass

        assert test_func._command_name == 'command'


class TestApplicationLoopMeta(object):
    def test_init(self, mocker):
        namespace = {
            'a': mocker.Mock(spec=[]),
            'b': 1,
            'c': mocker.Mock(_command_name='c1'),
            'd': mocker.Mock(_command_name='c2'),
        }

        result = apploop.ApplicationLoopMeta('TestClass', (object,), namespace)

        assert result._commands == {
            'c1': namespace['c'],
            'c2': namespace['d'],
        }


class TestApplicationLoop(object):
    def test_init(self, mocker):
        mock_QueuedSocket = mocker.patch.object(apploop.qsock, 'QueuedSocket')
        mock_Lock = mocker.patch.object(apploop.threading, 'Lock')

        result = apploop.ApplicationLoop('sock')

        assert result.sock == mock_QueuedSocket.return_value
        assert result._cli is None
        assert isinstance(result.display_buf, buffer.Buffer)
        assert result.display_buf_lock == mock_Lock.return_value
        assert isinstance(result.command_buf, buffer.Buffer)
        assert isinstance(
            result.command_buf.accept_action, buffer.AcceptAction
        )
        assert result.command_buf.accept_action.handler == result.execute
        mock_QueuedSocket.assert_called_once_with('sock')

    def test_recvloop_nocli(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': [
                qsock.Unsendable('unsendable'),
                'message 1',
                'message 2',
                None,
                qsock.Exit(),
                'message 3',
            ],
        })
        mocker.patch.object(apploop.qsock, 'QueuedSocket', return_value=sock)
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop(sock)

        obj._recvloop()

        sock.recv.assert_has_calls([
            mocker.call(),
            mocker.call(),
            mocker.call(),
            mocker.call(),
            mocker.call(),
        ])
        assert sock.recv.call_count == 5
        mock_display.assert_has_calls([
            mocker.call('ERROR: Failed to send: %r' % 'unsendable'),
            mocker.call('S: %r' % 'message 1'),
            mocker.call('S: %r' % 'message 2'),
            mocker.call('Connection closed'),
        ])
        assert mock_display.call_count == 4

    def test_recvloop_withcli(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': [
                qsock.Unsendable('unsendable'),
                'message 1',
                'message 2',
                None,
                qsock.Exit(),
                'message 3',
            ],
        })
        mocker.patch.object(apploop.qsock, 'QueuedSocket', return_value=sock)
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop(sock)
        obj._cli = mocker.Mock()

        obj._recvloop()

        sock.recv.assert_has_calls([
            mocker.call(),
            mocker.call(),
            mocker.call(),
            mocker.call(),
            mocker.call(),
        ])
        assert sock.recv.call_count == 5
        mock_display.assert_has_calls([
            mocker.call('ERROR: Failed to send: %r' % 'unsendable'),
            mocker.call('S: %r' % 'message 1'),
            mocker.call('S: %r' % 'message 2'),
            mocker.call('Connection closed'),
        ])
        assert mock_display.call_count == 4
        obj._cli.invalidate.assert_has_calls([
            mocker.call(),
            mocker.call(),
            mocker.call(),
            mocker.call(),
        ])
        assert obj._cli.invalidate.call_count == 4

    def test_display(self, mocker):
        mocker.patch.object(apploop.threading, 'Lock')
        mocker.patch.object(apploop.buffer, 'Buffer')
        obj = apploop.ApplicationLoop('sock')

        obj.display('text')

        obj.display_buf_lock.__enter__.assert_called_once_with()
        obj.display_buf.insert_text.assert_called_once_with('text\n')
        obj.display_buf_lock.__exit__.assert_called_once_with(None, None, None)

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

    def test_quit(self, mocker):
        mocker.patch.object(apploop.qsock, 'QueuedSocket')
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj.quit('args')

        obj.sock.exit.assert_called_once_with()
        mock_cli.set_return_value.assert_called_once_with(None)

    def test_send_failure(self, mocker):
        mocker.patch.object(apploop.qsock, 'QueuedSocket')
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
        assert not obj.sock.send.called

    def test_send_sent(self, mocker):
        mocker.patch.object(apploop.qsock, 'QueuedSocket')
        msg = mocker.Mock(__repr__=mocker.Mock(return_value='"a message"'))
        mock_interpret = mocker.patch.object(
            apploop.message.Message, 'interpret', return_value=msg
        )
        mock_display = mocker.patch.object(apploop.ApplicationLoop, 'display')
        obj = apploop.ApplicationLoop('sock')

        obj.send(['some', 'arguments'])

        mock_interpret.assert_called_once_with(['some', 'arguments'])
        obj.sock.send.assert_called_once_with(msg)
        mock_display.assert_called_once_with('C: "a message"')

    def test_run(self, mocker):
        mocker.patch.object(apploop.qsock, 'QueuedSocket')
        receiver = mocker.Mock(daemon=False)
        mock_Thread = mocker.patch.object(
            apploop.threading, 'Thread', return_value=receiver
        )
        mock_cli = mocker.patch.object(apploop.ApplicationLoop, 'cli')
        obj = apploop.ApplicationLoop('sock')

        obj.run()

        obj.sock.start.assert_called_once_with()
        mock_Thread.assert_called_once_with(target=obj._recvloop)
        assert receiver.daemon is True
        receiver.start.assert_called_once_with()
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
