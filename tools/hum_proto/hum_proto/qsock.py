# Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

import errno
import select
import socket
import threading

from six.moves import queue

from hum_proto import message


class SocketNotClosed(Exception):
    """
    Raised if we're given a new socket, but the old one isn't closed
    yet.
    """

    pass


class Unsendable(object):
    """
    Wraps a ``hum_proto.message.Message`` instance to report that the
    message couldn't be sent.
    """

    def __init__(self, msg):
        """
        Initialize an ``Unsendable`` instance.

        :param msg: The message that couldn't be sent.
        :type msg: ``hum_proto.message.Message``
        """

        self.msg = msg


class SetSock(object):
    """
    Wraps a socket object.  Used to signal the ``QueuedSocket`` loop
    that it should set up a new socket.
    """

    def __init__(self, sock):
        """
        Initialize a ``SetSock`` instance.

        :param sock: The new socket to use.
        :type sock: ``socket.socket``
        """

        self.sock = sock


class Exit(object):
    """
    Used to signal the ``QueuedSocket`` loop that it should exit.
    This object is also copied into the receive queue for the benefit
    of the receiver thread.
    """

    pass


# Special instances that can be sent even when the socket is closed
_sendable = (SetSock, Exit)


class QueuedSocket(object):
    """
    A ``socket.socket`` wrapper that uses queues to isolate the
    underlying socket from the receiver loop.  Uses the
    ``select.select()`` function to detect when messages have been
    received or sent and processes the sends and the receives
    synchronously; this ensures that the underlying socket can be
    wrapped if needed.
    """

    def __init__(self, sock):
        """
        Initialize a ``QueuedSocket`` instance.

        :param sock: The underlying socket to wrap.
        :type sock: ``socket.socket``
        """

        # The underlying socket object
        self._sock = sock

        # What we actually recv from or send to
        self._wrapper = sock

        # Recv and send queues
        self._recv_q = queue.Queue()
        self._send_q = queue.Queue()

        # The close status and its lock
        self._lock = threading.Lock()
        self._closed = False

        # Recv and send signaling filehandles
        self._sendsock, self._sendsignal = socket.socketpair()

        # Mark the signalling sockets nonblock
        self._sendsock.setblocking(0)

        # Socket sets
        self._recvable = [self._sock, self._sendsock]

    def _run(self):
        """
        The core receiver/sender loop for a ``QueuedSocket``.
        """

        while self._recvable:
            # Look for readable sockets
            recvable, _writable, _exceptable = select.select(
                self._recvable, [], [])

            # Process sends first
            if self._sendsock in recvable:
                self._send()

            # Now process recv
            if self._sock in recvable:
                self._recv()

    def _clear_sock(self, sock):
        """
        Clear the signaling socket.  The ``_run()`` method, the core loop
        of the ``QueuedSocket`` instance, uses a specially allocated
        socket pair to allow it to detect that data is awaiting in the
        ``_send_q``.  This routine reads the signal byte off the
        socket handle, ignoring an expected ``EAGAIN`` if we've fully
        emptied the buffer.

        :param sock: The socket to clear.
        :type sock: ``socket.socket``
        """

        try:
            # Read one byte from the socket
            sock.recv(1)
        except socket.error as err:
            # Ignore EAGAIN, since that's expected
            if err.errno == errno.EAGAIN:
                return
            raise

    def _send(self):
        """
        The send loop.  This is called to send messages that have been
        enqueued for sending.
        """

        try:
            while True:
                # Clear one byte off the send socket and get a message
                # without blocking
                self._clear_sock(self._sendsock)
                msg = self._send_q.get(False)

                if msg is None:
                    # Request to close the socket
                    self._close()
                elif isinstance(msg, SetSock):
                    # Request to update the socket
                    self._set_sock(msg.sock)
                elif isinstance(msg, Exit):
                    # Request to exit the loop
                    self._close()
                    self._recvable = []
                    self._recv_q.put(msg)
                    break
                else:
                    # Regular message to be sent
                    msg.send(self._wrapper)
        except queue.Empty:
            # We've emptied the queue!
            pass

    def _recv(self):
        """
        The message receiver.  This only reads one message, so that it
        cannot block and doesn't have to queue up anything.  This may
        cause ``select.select()`` in the ``_run()`` method to return
        immediately on the next call, but it prevents us from being
        blocked waiting for more data when we may have messages to
        send.
        """

        # Read only a single message at a time
        msg = message.Message.recv(self._wrapper)

        # Add the message to the queue
        self._recv_q.put(msg)

        # If it was EOF, take the appropriate action
        if not msg:
            self._close()

    def _close(self):
        """
        Close the socket.  This method is idempotent.
        """

        # First, check if we're already closed, then set _closed to
        # track the state
        with self._lock:
            if self._closed:
                return
            self._closed = True

        # Remove the socket from the set of sockets we're interested
        # in
        self._recvable.remove(self._sock)

        # Close the wrapper; we assume the wrapper will close the
        # underlying socket
        self._wrapper.close()

        # Clear the socket and its wrapper
        self._sock = None
        self._wrapper = None

    def _set_sock(self, sock):
        """
        Set a new socket to send to and receive from.  This is a
        counterpoint to the ``_close()`` method.

        :param sock: The new socket to monitor.
        :type sock: ``socket.socket``
        """

        # The underlying socket object
        self._sock = sock

        # What we actually recv from or send to
        self._wrapper = sock

        # We're no longer closed
        with self._lock:
            self._closed = False

        # Begin monitoring the new socket
        self._recvable.append(sock)

    def send(self, msg):
        """
        Send a message.  Note that the message is only enqueued, ready to
        be sent.

        :param msg: The message to send.
        :type msg: ``hum_proto.message.Message``
        """

        with self._lock:
            if not isinstance(msg, _sendable) and self._closed:
                # Can't send it, so report it
                self._recv_q.put(Unsendable(msg))
            else:
                # Enqueue the message and alert _run()
                self._send_q.put(msg)
                self._sendsignal.sendall(b'\0')

    def recv(self):
        """
        Receive a message.  This will block, waiting for a message to be
        received.

        :returns: The message received.  Usually, an instance of
                  ``hum_proto.message.Message``; however, other
                  special instances may be returned, such as
                  ``Unsendable`` if a message could not be sent, or
                  ``Exit`` if the loop has been instructed to exit.
        """

        return self._recv_q.get()

    def close(self):
        """
        Close the socket.  Note that this causes a message to be enqueued,
        and the socket may not be closed immediately.  This method is
        idempotent.
        """

        with self._lock:
            if not self._closed:
                self.send(None)

    def set_sock(self, sock):
        """
        Set a new socket.  The current socket must be closed.  Note that
        this causes a message to be enqueued, and the socket may not
        be set immediately.

        :param sock: The new socket to monitor.
        :type sock: ``socket.socket``

        :raises SocketNotClosed:
            The current socket has not been closed.
        """

        with self._lock:
            if self._closed:
                self.send(SetSock(sock))
            else:
                raise SocketNotClosed(
                    'The current socket must be closed before a new one '
                    'can be set.'
                )

    def exit(self):
        """
        Causes the core loop to exit.
        """

        self.send(Exit())

    def start(self):
        """
        Initiate the core loop.  This starts a new daemon thread running
        and returns to the caller.
        """

        thread = threading.Thread(target=self._run)
        thread.daemon = True
        thread.start()

    @property
    def closed(self):
        """
        Determine whether the socket has been closed.
        """

        with self._lock:
            return self._closed
