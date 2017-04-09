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

import shlex
import threading

from prompt_toolkit import application
from prompt_toolkit import buffer
from prompt_toolkit import interface
from prompt_toolkit.layout import containers
from prompt_toolkit.layout import controls
from prompt_toolkit.layout import dimension
from prompt_toolkit import shortcuts
import six

from hum_proto import lock_utils
from hum_proto import message


def command(func_or_name=None):
    """
    A decorator for marking ``ApplicationLoop`` methods that implement
    particular commands.  For instance, ``@command('spam')`` will mark
    a method as implementing the "spam" command.  If no name is given
    or the argument left off, the method name will be used for the
    command.

    :param func_or_name: A callable or a command name.

    :returns: If ``func_or_name`` is a callable, sets the
              ``_command_name`` attribute to the callable name, then
              returns the callable.  Otherwise, returns a function
              decorator which sets ``_command_name`` appropriately.
    """

    # The actual decorator
    def decorator(func):
        func._command_name = name or func.__name__
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

        # Save the commands
        cls._commands = commands


@six.add_metaclass(ApplicationLoopMeta)
class ApplicationLoop(object):
    """
    Core application loop for the Humboldt Protocol Analyzer.
    """

    def __init__(self, sock):
        """
        Initialize an ``ApplicationLoop`` instance.

        :param sock: A connected socket.
        :type sock: ``socket.socket``
        """

        # Save the socket and set up the lock
        self.sock = sock
        self.sock_lock = lock_utils.RWLock()

        # The command line interface
        self._cli = None

        # Initialize the display buffer
        self.display_buf = buffer.Buffer()
        self.display_buf_lock = threading.Lock()

        # Initialize the command buffer
        self.command_buf = buffer.Buffer(
            accept_action=buffer.AcceptAction(self.execute),
        )

    def _recvloop(self):
        """
        Receive messages from a Humboldt instance.  This acts in a loop,
        reading messages and displaying them until the connection is
        closed.
        """

        while True:
            # Read a message
            with self.sock_lock.read:
                msg = message.Message.recv(self.sock)

            if msg:
                # Display the message details
                self.display('S: %r' % msg)
            else:
                # Oh, closed the connection
                self.display('Connection closed')
                with self.sock_lock.write:
                    self.sock.close()
                    self.sock = None
                break

    def display(self, text):
        """
        Display text in the display pane.

        :param str text: The text to display.
        """

        # Could be called from 2 threads
        with self.display_buf_lock:
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

    @command
    def quit(self, args):
        """
        Exits the interpreter.  Arguments are ignored.

        :param list args: The list of arguments to the command.
        """

        self.cli.set_return_value(None)

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
        with self.sock_lock.read:
            if not self.sock:
                # Oops, guess it's closed
                self.display('ERROR: Socket has been closed')
                return

            msg.send(self.sock)

        # Display what we sent
        self.display('C: %r' % msg)

    def run(self):
        """
        Run the application loop.  This starts the receiver thread as a
        daemon thread and starts up the ``prompt_toolkit``-based UI.
        """

        # Spawn the receiver thread
        receiver = threading.Thread(target=self._recvloop)
        receiver.daemon = True
        receiver.start()

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
