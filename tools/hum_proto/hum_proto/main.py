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

import cli_tools

from hum_proto import apploop


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
    sock = apploop.connect(endpoint)

    # Now, initialize the application loop and run it
    app = apploop.ApplicationLoop(sock)
    app.run()

    # Close the socket
    if app.sock:
        app.sock.close()
