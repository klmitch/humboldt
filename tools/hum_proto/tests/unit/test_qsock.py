import errno
import os
import socket

import pytest
from six.moves import queue

from hum_proto import qsock


def make_sockerr(errcode):
    return socket.error(errcode, os.strerror(errcode))


class TestUnsendable(object):
    def test_init(self):
        result = qsock.Unsendable('spam')

        assert result.msg == 'spam'


class TestSetSock(object):
    def test_init(self):
        result = qsock.SetSock('spam')

        assert result.sock == 'spam'


class TestQueuedSocket(object):
    def test_init(self, mocker):
        mock_Queue = mocker.patch.object(
            qsock.queue, 'Queue', side_effect=['recv_q', 'send_q']
        )
        mock_Lock = mocker.patch.object(qsock.threading, 'Lock')
        sendsock = mocker.Mock()
        sendsignal = mocker.Mock()
        mock_socketpair = mocker.patch.object(
            qsock.socket, 'socketpair', return_value=[sendsock, sendsignal]
        )

        result = qsock.QueuedSocket('sock')

        assert result._sock == 'sock'
        assert result._wrapper == 'sock'
        assert result._recv_q == 'recv_q'
        assert result._send_q == 'send_q'
        assert result._lock == mock_Lock.return_value
        assert result._closed is False
        assert result._sendsock == sendsock
        assert result._sendsignal == sendsignal
        assert result._recvable == ['sock', sendsock]
        mock_Queue.assert_has_calls([
            mocker.call(),
            mocker.call(),
        ])
        assert mock_Queue.call_count == 2
        mock_Lock.assert_called_once_with()
        mock_socketpair.assert_called_once_with()
        sendsock.setblocking.assert_called_once_with(0)
        assert not sendsignal.setblocking.called

    def get_obj(self, mocker, sock=None, wrapper=None, recv_q=None,
                send_q=None, lock=None, sendsock=None, sendsignal=None):
        mocker.patch.object(
            qsock.queue, 'Queue', side_effect=[
                recv_q or mocker.Mock(),
                send_q or mocker.Mock(),
            ],
        )
        mocker.patch.object(
            qsock.threading, 'Lock', return_value=lock or mocker.MagicMock()
        )
        mocker.patch.object(
            qsock.socket, 'socketpair', return_value=[
                sendsock or mocker.Mock(),
                sendsignal or mocker.Mock(),
            ],
        )

        obj = qsock.QueuedSocket(sock or mocker.Mock())

        # Make _wrapper distinct
        obj._wrapper = wrapper or mocker.Mock()

        return obj

    def test_run_internal_send(self, mocker):
        def fake_send():
            obj._recvable = []
        mock_send = mocker.patch.object(
            qsock.QueuedSocket, '_send', side_effect=fake_send,
        )
        mock_recv = mocker.patch.object(qsock.QueuedSocket, '_recv')
        obj = self.get_obj(mocker)
        mock_select = mocker.patch.object(
            qsock.select, 'select', side_effect=[
                ([obj._sendsock], [], []),
                ([obj._sock], [], []),
            ],
        )

        obj._run()

        mock_select.assert_called_once_with(
            [obj._sock, obj._sendsock], [], []
        )
        mock_send.assert_called_once_with()
        assert not mock_recv.called

    def test_run_internal_recv(self, mocker):
        def fake_recv():
            obj._recvable = []
        mock_send = mocker.patch.object(qsock.QueuedSocket, '_send')
        mock_recv = mocker.patch.object(
            qsock.QueuedSocket, '_recv', side_effect=fake_recv,
        )
        obj = self.get_obj(mocker)
        mock_select = mocker.patch.object(
            qsock.select, 'select', side_effect=[
                ([obj._sock], [], []),
                ([obj._sendsock], [], []),
            ],
        )

        obj._run()

        mock_select.assert_called_once_with(
            [obj._sock, obj._sendsock], [], []
        )
        assert not mock_send.called
        mock_recv.assert_called_once_with()

    def test_run_internal_loops(self, mocker):
        def fake_recv():
            obj._recvable = []
        mock_send = mocker.patch.object(qsock.QueuedSocket, '_send')
        mock_recv = mocker.patch.object(
            qsock.QueuedSocket, '_recv', side_effect=fake_recv,
        )
        obj = self.get_obj(mocker)
        mock_select = mocker.patch.object(
            qsock.select, 'select', side_effect=[
                ([obj._sendsock], [], []),
                ([obj._sock], [], []),
            ],
        )

        obj._run()

        mock_select.assert_has_calls([
            mocker.call([obj._sock, obj._sendsock], [], []),
            mocker.call([obj._sock, obj._sendsock], [], []),
        ])
        assert mock_select.call_count == 2
        mock_send.assert_called_once_with()
        mock_recv.assert_called_once_with()

    def test_clear_sock_base(self, mocker):
        sock = mocker.Mock()
        obj = self.get_obj(mocker)

        obj._clear_sock(sock)

        sock.recv.assert_called_once_with(1)

    def test_clear_sock_eagain(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': make_sockerr(errno.EAGAIN),
        })
        obj = self.get_obj(mocker)

        obj._clear_sock(sock)

        sock.recv.assert_called_once_with(1)

    def test_clear_sock_other(self, mocker):
        sock = mocker.Mock(**{
            'recv.side_effect': make_sockerr(errno.ENOENT),
        })
        obj = self.get_obj(mocker)

        with pytest.raises(socket.error):
            obj._clear_sock(sock)

        sock.recv.assert_called_once_with(1)

    def test_send_internal_close(self, mocker):
        mock_clear_sock = mocker.patch.object(
            qsock.QueuedSocket, '_clear_sock'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        mock_set_sock = mocker.patch.object(qsock.QueuedSocket, '_set_sock')
        obj = self.get_obj(mocker)
        obj._send_q.get.side_effect = [
            None,
            queue.Empty,
        ]

        obj._send()

        assert obj._recvable == [obj._sock, obj._sendsock]
        mock_clear_sock.assert_has_calls([
            mocker.call(obj._sendsock),
            mocker.call(obj._sendsock),
        ])
        assert mock_clear_sock.call_count == 2
        obj._send_q.get.assert_has_calls([
            mocker.call(False),
            mocker.call(False),
        ])
        assert obj._send_q.get.call_count == 2
        mock_close.assert_called_once_with()
        assert not mock_set_sock.called
        assert not obj._recv_q.put.called

    def test_send_internal_setsock(self, mocker):
        mock_clear_sock = mocker.patch.object(
            qsock.QueuedSocket, '_clear_sock'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        mock_set_sock = mocker.patch.object(qsock.QueuedSocket, '_set_sock')
        obj = self.get_obj(mocker)
        obj._send_q.get.side_effect = [
            qsock.SetSock('new'),
            queue.Empty,
        ]

        obj._send()

        assert obj._recvable == [obj._sock, obj._sendsock]
        mock_clear_sock.assert_has_calls([
            mocker.call(obj._sendsock),
            mocker.call(obj._sendsock),
        ])
        assert mock_clear_sock.call_count == 2
        obj._send_q.get.assert_has_calls([
            mocker.call(False),
            mocker.call(False),
        ])
        assert obj._send_q.get.call_count == 2
        assert not mock_close.called
        mock_set_sock.assert_called_once_with('new')
        assert not obj._recv_q.put.called

    def test_send_internal_exit(self, mocker):
        mock_clear_sock = mocker.patch.object(
            qsock.QueuedSocket, '_clear_sock'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        mock_set_sock = mocker.patch.object(qsock.QueuedSocket, '_set_sock')
        obj = self.get_obj(mocker)
        exit_ = qsock.Exit()
        obj._send_q.get.side_effect = [
            exit_,
            'message',
            queue.Empty,
        ]

        obj._send()

        assert obj._recvable == []
        mock_clear_sock.assert_called_once_with(obj._sendsock)
        obj._send_q.get.assert_called_once_with(False)
        mock_close.assert_called_once_with()
        assert not mock_set_sock.called
        obj._recv_q.put.assert_called_once_with(exit_)

    def test_send_internal_message(self, mocker):
        mock_clear_sock = mocker.patch.object(
            qsock.QueuedSocket, '_clear_sock'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        mock_set_sock = mocker.patch.object(qsock.QueuedSocket, '_set_sock')
        obj = self.get_obj(mocker)
        msg = mocker.Mock()
        obj._send_q.get.side_effect = [
            msg,
            queue.Empty,
        ]

        obj._send()

        assert obj._recvable == [obj._sock, obj._sendsock]
        mock_clear_sock.assert_has_calls([
            mocker.call(obj._sendsock),
            mocker.call(obj._sendsock),
        ])
        assert mock_clear_sock.call_count == 2
        obj._send_q.get.assert_has_calls([
            mocker.call(False),
            mocker.call(False),
        ])
        assert obj._send_q.get.call_count == 2
        assert not mock_close.called
        assert not mock_set_sock.called
        assert not obj._recv_q.put.called
        msg.send.assert_called_once_with(obj._wrapper)

    def test_send_internal_loop(self, mocker):
        mock_clear_sock = mocker.patch.object(
            qsock.QueuedSocket, '_clear_sock'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        mock_set_sock = mocker.patch.object(qsock.QueuedSocket, '_set_sock')
        obj = self.get_obj(mocker)
        msg1 = mocker.Mock()
        msg2 = mocker.Mock()
        msg3 = mocker.Mock()
        obj._send_q.get.side_effect = [
            msg1,
            msg2,
            queue.Empty,
            msg3,
        ]

        obj._send()

        assert obj._recvable == [obj._sock, obj._sendsock]
        mock_clear_sock.assert_has_calls([
            mocker.call(obj._sendsock),
            mocker.call(obj._sendsock),
            mocker.call(obj._sendsock),
        ])
        assert mock_clear_sock.call_count == 3
        obj._send_q.get.assert_has_calls([
            mocker.call(False),
            mocker.call(False),
            mocker.call(False),
        ])
        assert obj._send_q.get.call_count == 3
        assert not mock_close.called
        assert not mock_set_sock.called
        assert not obj._recv_q.put.called
        msg1.send.assert_called_once_with(obj._wrapper)
        msg2.send.assert_called_once_with(obj._wrapper)
        assert not msg3.send.called

    def test_recv_internal_base(self, mocker):
        mock_recv = mocker.patch.object(
            qsock.message.Message, 'recv', return_value='message'
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        obj = self.get_obj(mocker)

        obj._recv()

        mock_recv.assert_called_once_with(obj._wrapper)
        obj._recv_q.put.assert_called_once_with('message')
        assert not mock_close.called

    def test_recv_internal_eof(self, mocker):
        mock_recv = mocker.patch.object(
            qsock.message.Message, 'recv', return_value=None
        )
        mock_close = mocker.patch.object(qsock.QueuedSocket, '_close')
        obj = self.get_obj(mocker)

        obj._recv()

        mock_recv.assert_called_once_with(obj._wrapper)
        obj._recv_q.put.assert_called_once_with(None)
        mock_close.assert_called_once_with()

    def test_close_internal_base(self, mocker):
        wrapper = mocker.Mock()
        obj = self.get_obj(mocker, wrapper=wrapper)

        obj._close()

        assert obj._closed is True
        assert obj._recvable == [obj._sendsock]
        assert obj._sock is None
        assert obj._wrapper is None
        obj._lock.__enter__.assert_called_once_with()
        obj._lock.__exit__.assert_called_once_with(None, None, None)
        wrapper.close.assert_called_once_with()

    def test_close_internal_closed(self, mocker):
        wrapper = mocker.Mock()
        obj = self.get_obj(mocker, wrapper=wrapper)
        obj._closed = True

        obj._close()

        assert obj._closed is True
        assert obj._sock is not None
        assert obj._recvable == [obj._sock, obj._sendsock]
        assert obj._wrapper is not None
        obj._lock.__enter__.assert_called_once_with()
        obj._lock.__exit__.assert_called_once_with(None, None, None)
        assert not wrapper.close.called

    def test_set_sock_internal(self, mocker):
        obj = self.get_obj(mocker)
        obj._closed = True
        obj._sock = None
        obj._wrapper = None
        obj._recvable = [obj._sendsock]

        obj._set_sock('sock')

        assert obj._sock == 'sock'
        assert obj._wrapper == 'sock'
        assert obj._closed is False
        assert obj._recvable == [obj._sendsock, 'sock']
        obj._lock.__enter__.assert_called_once_with()
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_message_open(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)

        obj.send('message')

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_Unsendable.called
        assert not obj._recv_q.put.called
        obj._send_q.put.assert_called_once_with('message')
        obj._sendsignal.sendall.assert_called_once_with(b'\0')
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_message_closed(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)
        obj._closed = True

        obj.send('message')

        obj._lock.__enter__.assert_called_once_with()
        mock_Unsendable.assert_called_once_with('message')
        obj._recv_q.put.assert_called_once_with(mock_Unsendable.return_value)
        assert not obj._send_q.put.called
        assert not obj._sendsignal.sendall.called
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_setsock_open(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)
        msg = qsock.SetSock('sock')

        obj.send(msg)

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_Unsendable.called
        assert not obj._recv_q.put.called
        obj._send_q.put.assert_called_once_with(msg)
        obj._sendsignal.sendall.assert_called_once_with(b'\0')
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_setsock_closed(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)
        obj._closed = True
        msg = qsock.SetSock('sock')

        obj.send(msg)

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_Unsendable.called
        assert not obj._recv_q.put.called
        obj._send_q.put.assert_called_once_with(msg)
        obj._sendsignal.sendall.assert_called_once_with(b'\0')
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_exit_open(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)
        msg = qsock.Exit()

        obj.send(msg)

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_Unsendable.called
        assert not obj._recv_q.put.called
        obj._send_q.put.assert_called_once_with(msg)
        obj._sendsignal.sendall.assert_called_once_with(b'\0')
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_send_exit_closed(self, mocker):
        mock_Unsendable = mocker.patch.object(qsock, 'Unsendable')
        obj = self.get_obj(mocker)
        obj._closed = True
        msg = qsock.Exit()

        obj.send(msg)

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_Unsendable.called
        assert not obj._recv_q.put.called
        obj._send_q.put.assert_called_once_with(msg)
        obj._sendsignal.sendall.assert_called_once_with(b'\0')
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_recv(self, mocker):
        obj = self.get_obj(mocker)

        result = obj.recv()

        assert result == obj._recv_q.get.return_value
        obj._recv_q.get.assert_called_once_with()

    def test_close_open(self, mocker):
        mock_send = mocker.patch.object(qsock.QueuedSocket, 'send')
        obj = self.get_obj(mocker)

        obj.close()

        obj._lock.__enter__.assert_called_once_with()
        mock_send.assert_called_once_with(None)
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_close_closed(self, mocker):
        mock_send = mocker.patch.object(qsock.QueuedSocket, 'send')
        obj = self.get_obj(mocker)
        obj._closed = True

        obj.close()

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_send.called
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_set_sock_open(self, mocker):
        mock_SetSock = mocker.patch.object(qsock, 'SetSock')
        mock_send = mocker.patch.object(qsock.QueuedSocket, 'send')
        obj = self.get_obj(mocker)

        with pytest.raises(qsock.SocketNotClosed):
            obj.set_sock('sock')

        obj._lock.__enter__.assert_called_once_with()
        assert not mock_SetSock.called
        assert not mock_send.called
        obj._lock.__exit__.assert_called_once_with(
            qsock.SocketNotClosed, mocker.ANY, mocker.ANY
        )

    def test_set_sock_closed(self, mocker):
        mock_SetSock = mocker.patch.object(qsock, 'SetSock')
        mock_send = mocker.patch.object(qsock.QueuedSocket, 'send')
        obj = self.get_obj(mocker)
        obj._closed = True

        obj.set_sock('sock')

        obj._lock.__enter__.assert_called_once_with()
        mock_SetSock.assert_called_once_with('sock')
        mock_send.assert_called_once_with(mock_SetSock.return_value)
        obj._lock.__exit__.assert_called_once_with(None, None, None)

    def test_exit(self, mocker):
        mock_Exit = mocker.patch.object(qsock, 'Exit')
        mock_send = mocker.patch.object(qsock.QueuedSocket, 'send')
        obj = self.get_obj(mocker)

        obj.exit()

        mock_Exit.assert_called_once_with()
        mock_send.assert_called_once_with(mock_Exit.return_value)

    def test_start(self, mocker):
        thread = mocker.Mock(daemon=False)
        mock_Thread = mocker.patch.object(
            qsock.threading, 'Thread', return_value=thread
        )
        obj = self.get_obj(mocker)

        obj.start()

        assert thread.daemon is True
        mock_Thread.assert_called_once_with(target=obj._run)
        thread.start.assert_called_once_with()

    def test_closed(self, mocker):
        obj = self.get_obj(mocker)

        assert obj.closed is False
        obj._lock.__enter__.assert_called_once_with()
        obj._lock.__exit__.assert_called_once_with(None, None, None)
