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

import sys
import socket

import cli_tools
import six

from hum_proto import apploop


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


@cli_tools.argument(
    'endpoint',
    help='The endpoint to which to connect.  This may be a file name for a '
    'local socket; a hostname (optionally followed by a ":" and a port '
    'number); an IPv4 address (optionally followed by a ":" and a port '
    'number); or an IPv6 address enclosed in square brackets (again, '
    'optionally followed by a ":" and a port number).  If a port number is '
    'not specified, the default of 7300 will be used.',
)
@cli_tools.argument(
    '--debug', '-d',
    action='store_true',
    help='Enable debugging mode.',
)
def main(endpoint):
    """
    Start a full-screen protocol analyzer connected to a specified
    Humboldt server.

    :param str endpoint: The endpoint to which to connect.
    """

    # First, connect to the specified endpoint
    sock = connect(endpoint)

    # Now, initialize the application loop and run it
    app = apploop.ApplicationLoop(sock)
    app.run()

    # Close the socket
    if app.sock:
        app.sock.close()
