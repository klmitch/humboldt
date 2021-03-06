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
import os
import shlex
import socket
import sys

from prompt_toolkit import application
from prompt_toolkit import buffer
from prompt_toolkit import interface
from prompt_toolkit.layout import containers
from prompt_toolkit.layout import controls
from prompt_toolkit.layout import dimension
from prompt_toolkit import shortcuts
import six

from hum_proto import message


def _mksockerr(err):
    """
    Construct a ``socket.error`` instance based on a specified socket
    error number.

    :param int err: A value from ``errno``.

    :returns: The specified socket error.
    :rtype: ``socket.error``
    """

    return socket.error(err, os.strerror(err))


def connect(address):
    """
    Create a connection to a specified address.  The address may be a
    local path, or it may be a host name, an IPv4 address, or an IPv6
    address (optionally surrounded by square brackets).  A port may be
    specified by separating it from the host name or address with a
    colon.  If a port is not specified, it defaults to "7300".

    :param str address: The address to connect to.

    :returns: A connected socket.
    """

    # Is it a path?
    if '/' in address:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        sock.connect(address)
        return sock

    # OK, it must be a host and port
    host, sep, port = address.rpartition(':')
    if not sep or not port.isdigit():
        host = address
        port = 7300
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]

    # Connect to the host
    lasterr = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
            host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
    ):
        try:
            sock = socket.socket(family, socktype, proto)
            sock.connect(sockaddr)
            return sock
        except Exception:
            # Failed; save the last error
            lasterr = sys.exc_info()

    # Failed to connect to a host
    six.reraise(*lasterr)


def command(func_or_name=None, aliases=None):
    """
    A decorator for marking ``ApplicationLoop`` methods that implement
    particular commands.  For instance, ``@command('spam')`` will mark
    a method as implementing the "spam" command.  If no name is given
    or the argument left off, the method name will be used for the
    command.

    :param func_or_name: A callable or a command name.
    :param list aliases: A list of aliases for the command.

    :returns: If ``func_or_name`` is a callable, sets the
              ``_command_name`` attribute to the callable name, then
              returns the callable.  Otherwise, returns a function
              decorator which sets ``_command_name`` appropriately.
    """

    # The actual decorator
    def decorator(func):
        func._command_name = name or func.__name__
        func._command_aliases = aliases or []
        return func

    # If it was a callable, use the function name
    if callable(func_or_name):
        name = None
        return decorator(func_or_name)

    # Return the decorator
    name = func_or_name
    return decorator


class ApplicationLoopMeta(type):
    """
    A metaclass for the ``ApplicationLoop`` class.  This metaclass
    searches the namespace for methods decorated with the ``@command``
    decorator and constructs a dictionary mapping command names to the
    underlying functions.
    """

    def __init__(cls, name, bases, namespace):
        """
        Initialize a newly constructed class.

        :param str name: The name of the new class.
        :param tuple bases: A tuple of the class's base classes.
        :param dict namespace: The new class's namespace.
        """

        # Compile a dictionary of commands
        commands = {}

        # Search through the namespace values...
        for val in namespace.values():
            if callable(val) and hasattr(val, '_command_name'):
                # We have a command!
                commands[val._command_name] = val

                # Also set up its aliases
                for alias in val._command_aliases:
                    commands[alias] = val

        # Save the commands
        cls._commands = commands


@six.add_metaclass(ApplicationLoopMeta)
class ApplicationLoop(object):
    """
    Core application loop for the Humboldt Protocol Analyzer.
    """

    def __init__(self, sock, sslctx_cli, sslctx_srv):
        """
        Initialize an ``ApplicationLoop`` instance.

        :param sock: A connected socket.
        :type sock: ``socket.socket``
        :param sslctx_cli: An SSL context to use for client-side SSL
                           support.
        :type sslctx_cli: ``hum_proto.ssl_utils.SSLContext``
        :param sslctx_srv: An SSL context to use for server-side SSL
                           support.
        :type sslctx_srv: ``hum_proto.ssl_utils.SSLContext``
        """

        # Save the socket and SSL context
        self.sock = sock
        self.sslctx_cli = sslctx_cli
        self.sslctx_srv = sslctx_srv

        # The command line interface
        self._cli = None

        # Initialize the display buffer
        self.display_buf = buffer.Buffer()

        # Initialize the command buffer
        self.command_buf = buffer.Buffer(
            accept_action=buffer.AcceptAction(self.execute),
        )

    def _close(self):
        """
        Close the socket.
        """

        # Is it closed already?
        if self.sock is None:
            return

        # Display a message to alert the user to the closed connection
        self.display('Connection closed')

        # Close it
        self.cli.eventloop.remove_reader(self.sock)
        self.sock.close()
        self.sock = None

    def _recv(self):
        """
        Receive a message from the socket.
        """

        # Read a message
        msg = message.Message.recv(self.sock)

        if msg is None:
            # Close the connection
            self._close()
        else:
            # Display the message
            self.display('S: %r' % msg)

            # If there's a reaction, invoke it
            if msg.reaction:
                msg.reaction(self)

        # Make sure we redraw to display the message
        self.cli.invalidate()

    def display(self, text):
        """
        Display text in the display pane.

        :param str text: The text to display.
        """

        # Display the text
        self.display_buf.insert_text('%s\n' % text)

    def execute(self, cli, doc):
        """
        Execute a command.  This is called whenever the "enter" key is
        pressed in the command buffer.

        :param cli: The command line interface.
        :type cli: ``prompt_toolkit.interface.CommandLineInterface``
        :param doc: The document contained in the command buffer.
        :type doc: ``prompt_toolkit.document.Document``
        """

        # Do nothing if the command is empty
        if not doc.text:
            return

        # Split the command
        cmd = shlex.split(doc.text)

        # Reset the input buffer
        self.command_buf.reset(append_to_history=True)

        # What do we do?
        if cmd[0] not in self._commands:
            self.display('ERROR: Unknown command "%s"' % cmd[0])
        else:
            self._commands[cmd[0]](self, cmd[1:])

    @command(aliases=['quit'])
    def exit(self, args):
        """
        Exits the interpreter.  Arguments are ignored.

        :param list args: The list of arguments to the command.
        """

        # Close the connection
        self._close()

        # Signal the interface to exit
        self.cli.set_return_value(None)

    @command
    def close(self, args):
        """
        Close the connection.  Arguments are ignored.

        :param list args: The list of arguments to the command.
        """

        # Close the connection
        self._close()

    @command
    def connect(self, args):
        """
        Connect to the specified Humboldt endpoint.

        :param list args: The list of arguments to the command.
        """

        # Make sure we have an address
        if len(args) != 1:
            self.display(
                'ERROR: too %s arguments for connect' %
                ('many' if len(args) > 1 else 'few')
            )
            return

        # Make the new connection
        try:
            new_sock = connect(args[0])
        except Exception as err:
            # Hmmm, couldn't connect?
            self.display(
                'ERROR: Unable to connect to %s: %s' % (args[0], err)
            )
            return

        # Set up the new socket
        self.setsock(new_sock)
        self.display('Connected to %s' % args[0])

    @command
    def send(self, args):
        """
        Construct a message and send it to the connected Humboldt
        instance.

        :param list args: The list of arguments to the command.
        """

        # Interpret the message description
        try:
            msg = message.Message.interpret(args)
        except message.CommandError as err:
            self.display(
                'ERROR: Failed to understand message to send: %s' % err
            )
            return

        # Send the message
        if self.sock is None:
            self.display('ERROR: Connection is closed')
            return

        # Send the message
        self.send_msg(msg)

    def send_msg(self, msg):
        """
        Send a message to the connected Humboldt instance.

        :param msg: The message to send.
        :type msg: ``humboldt.message.Message``
        """

        msg.send(self.sock)

        # Display what we sent
        self.display('C: %r' % msg)

        # If there's an action, invoke it
        if msg.action:
            msg.action(self)

    def setsock(self, newsock):
        """
        Set up a new socket to monitor.

        :param newsock: The new socket to monitor.
        :type newsock: ``socket.socket``
        """

        # Make sure the current socket is closed
        if self.sock:
            self._close()

        # Save the new socket and set it up for monitoring
        self.sock = newsock
        self.cli.eventloop.add_reader(self.sock, self._recv)

    def wrap(self, wrapper, *args, **kwargs):
        """
        Wrap the socket.

        :param wrapper: A callable of at least one argument.  This
                        callable must take a socket object as its
                        first parameter, and must return a new
                        socket-compatible object that will be used for
                        subsequent message sending and receiving.
        :param *args: Additional positional arguments for the wrapper.
                      These will be passed after the socket object.
        :param **kwargs: Additional keyword arguments for the wrapper.

        :raises socket.error:
            If the socket has been closed, raises a ``socket.error``
            with the error number ``errno.EBADF``.
        """

        # If the socket is closed, there's nothing we can do
        if not self.sock:
            raise _mksockerr(errno.EBADF)

        # Wrap our socket
        self.cli.eventloop.remove_reader(self.sock)
        try:
            self.sock = wrapper(self.sock, *args, **kwargs)
        finally:
            self.cli.eventloop.add_reader(self.sock, self._recv)

    def run(self):
        """
        Run the application loop.  This starts listening to the socket and
        starts up the ``prompt_toolkit``-based UI.
        """

        # Listen to the socket
        if self.sock:
            self.cli.eventloop.add_reader(self.sock, self._recv)

        # Start the ui
        self.cli.run()

    @property
    def cli(self):
        """
        Retrieve the ``prompt_toolkit`` command line interface object.
        """

        if self._cli is None:
            # Construct the layout
            layout = containers.HSplit([
                # The display window
                containers.Window(
                    content=controls.BufferControl('display'),
                    wrap_lines=True,
                ),

                # The horizontal separator
                containers.Window(
                    height=dimension.LayoutDimension.exact(1),
                    content=controls.FillControl('-'),
                ),

                # The command window
                containers.Window(
                    height=dimension.LayoutDimension.exact(3),
                    content=controls.BufferControl('command'),
                    wrap_lines=True,
                ),
            ])

            # Construct the application
            app = application.Application(
                layout=layout,
                mouse_support=True,
                use_alternate_screen=True,
                buffers={
                    'display': self.display_buf,
                    'command': self.command_buf,
                },
                initial_focussed_buffer='command',
            )

            # Construct the event loop
            loop = shortcuts.create_eventloop()

            # Construct the command line interface
            self._cli = interface.CommandLineInterface(
                application=app,
                eventloop=loop,
            )

        return self._cli
