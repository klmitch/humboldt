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

from hum_proto import message


class StartTLSError(message.Message):
    """
    Represent an error for the STARTTLS exchange.  Humboldt sends
    these messages when it is unable to accept a TLS exchange.
    """

    PROTOCOL = 2
    default_carrier_flags = 'error'


class StartTLSReply(message.Message):
    """
    Represent a reply for the STARTTLS exchange.  Humboldt sends these
    messages when it accepts a STARTTLS request and is ready to accept
    a TLS exchange.
    """

    PROTOCOL = 2
    default_carrier_flags = 'reply'

    def _getpeer(self, sock):
        """
        Given an SSL socket, obtain the peer name.  If the common name is
        available, returns that; otherwise, forms a distinguished name
        from all the components of the certificate subject.

        :param sock: An SSL socket.
        :type sock: ``ssl.SSLSocket``

        :returns: A displayable peer certificate name.
        :rtype: ``str``
        """

        # Get the peer certificate
        peer = sock.getpeercert()
        if not peer:
            return None

        # Begin building a full distinguished name, which we'll return
        # if we don't find a 'commonName' RDN
        distinguished = []
        for rdn in peer['subject']:
            # Build up the attributes of the RDN
            attrs = []
            for name, value in rdn:
                attrs.append('%s=%s' % (name, value))

            # Construct the RDN string
            rdn_str = '/'.join(attrs)

            # If it's the common name, chop that out and return it
            if rdn_str.startswith('commonName='):
                return rdn_str[len('commonName='):]

            # Add it to the distinguished name
            distinguished.append(rdn_str)

        # Return the full distinguished name
        return ', '.join(distinguished)

    def action(self, apploop):
        """
        An action is invoked when a message is sent.  This action is
        designed to start a TLS exchange in server mode.

        :param apploop: The application loop.
        :type apploop: ``hum_proto.apploop.ApplicationLoop``
        """

        # Wrap the socket
        apploop.display('Initiating TLS (server mode)')
        try:
            apploop.wrap(apploop.sslctx_srv.wrap_socket, server_side=True)
        except Exception as err:
            apploop.display('TLS exchange failed: %s' % err)
            return

        # Get the peer certificate information and display it
        peer = self._getpeer(apploop.sock)
        if peer:
            apploop.display('TLS exchange succeeded; peer: %s' % peer)
        else:
            apploop.display('TLS exchange succeeded; no peer information')

    def reaction(self, apploop):
        """
        A reaction is invoked when a message is received.  This reaction
        is designed to start a TLS exchange in client mode.

        :param apploop: The application loop.
        :type apploop: ``hum_proto.apploop.ApplicationLoop``
        """

        # Wrap the socket
        apploop.display('Initiating TLS (client mode)')
        try:
            apploop.wrap(apploop.sslctx_cli.wrap_socket, server_side=False)
        except Exception as err:
            apploop.display('TLS exchange failed: %s' % err)
            return

        # Get the peer certificate information and display it
        apploop.display('TLS exchange succeeded; peer: %s' %
                        self._getpeer(apploop.sock))


class StartTLSRequest(message.Message):
    """
    Represent a request for the STARTTLS exchange.  Clients send these
    messages when they wish to initiate a TLS exchange.
    """

    PROTOCOL = 2


def _protocol2(**kwargs):
    """
    Decode protocol 2 messages.

    :param carrier_flags: The carrier protocol flags.

    :returns: An appropriate instance of a subclass of ``Message``
              representing the protocol 0 message.
    :rtype: ``Message``
    """

    # Handle error and reply flags
    if 'error' in kwargs['carrier_flags']:
        return StartTLSError(**kwargs)
    elif 'reply' in kwargs['carrier_flags']:
        return StartTLSReply(**kwargs)

    return StartTLSRequest(**kwargs)
