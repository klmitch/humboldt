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

import collections
import struct
import uuid

from hum_proto import attrs
from hum_proto import enum
from hum_proto import message


class ConnectionState(message.Message):
    """
    Represent a connection state message.
    """

    PROTOCOL = 0

    # A struct format describing the contents of a connection state
    # reply
    _message = struct.Struct('>BB2x16s')

    # Attributes specific to this message type to display
    MSG_ATTRS = collections.OrderedDict([
        ('flags', message.flagger),
        ('status', message.enumer),
        ('node_id', str),
    ])

    default_carrier_flags = 'reply'

    # Flags for the connection state message
    flags = enum.EnumSet(
        enum.Enum('client', 0x80, True),
        enum.Enum('secure', 0x40, True),
        enum.Enum('tls', 0x20, True),
    ).flags

    # Status is an enumeration that can take on a narrow range of
    # values
    status = enum.EnumSet(
        enum.Enum('INITIAL', 0),
        enum.Enum('CLIENT', 1),
        enum.Enum('AUTH', 2),
        enum.Enum('ERROR', 255),
    ).attr

    @classmethod
    def _decode(cls, **kwargs):
        """
        Decode a connection state message.

        :param bytes payload: The connection state message.
        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the
                  connection state message class.
        :rtype: ``ConnectionState``
        """

        # Extract data from the payload
        flags, status, node_id = cls._message.unpack(kwargs['payload'])

        # Transform the flags and UUID as appropriate
        flags = cls.flags.eset.flagset(flags)
        node_id = uuid.UUID(bytes=node_id)

        return cls(flags, status, node_id, **kwargs)

    def __init__(self, flags=None, status=0, node_id=None, **kwargs):
        """
        Initialize a ``ConnectionState`` instance.

        :param flags: The connection state flags.
        :param status: The connection status.
        :param node_id: The node UUID.
        :param **kwargs: Additional keyword arguments to use for
                         initializing the ``Message`` portion.
        """

        # Initialize the Message
        super(ConnectionState, self).__init__(**kwargs)

        # Save the data
        self.flags = flags
        self.status = status
        self.node_id = node_id

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        return self._message.pack(
            int(self.flags), int(self.status), self.node_id.bytes
        )

    @attrs.FilterAttr
    def node_id(self, node_id):
        """
        The node ID.  This will be an instance of ``uuid.UUID``.
        """

        # First, canonicalize it
        if node_id is None:
            node_id = uuid.UUID('0' * 32)
        elif not isinstance(node_id, uuid.UUID):
            node_id = uuid.UUID(node_id)

        return node_id


class RequestConnectionState(message.Message):
    """
    Represent a request for connection state message.  This message
    has no payload.
    """

    PROTOCOL = 0


# A named tuple for metadata about error codes
ErrorData = collections.namedtuple('ErrorData', ['type_', 'struct'])


class ConnectionError(message.Message):
    """
    Represent a connection error message.
    """

    PROTOCOL = 0

    # Structs and types for collecting the error code and decoding the
    # error arguments
    _error = struct.Struct('>B')
    _args = {
        0: None,
        1: ErrorData(
            collections.namedtuple('UnknownProtocol', ['protocol']),
            struct.Struct('>B'),
        ),
        2: ErrorData(
            collections.namedtuple('MalformedMessage', ['protocol']),
            struct.Struct('>B'),
        ),
        3: None,
    }

    MSG_ATTRS = collections.OrderedDict([
        ('error', message.enumer),
        ('args', message.splitter),
    ])

    default_carrier_flags = 'error'

    # Recognized error codes
    error = enum.EnumSet(
        enum.Enum('no error', 0),
        enum.Enum('unknown protocol', 1),
        enum.Enum('malformed message', 2),
        enum.Enum('not authorized', 3),
    ).attr

    @classmethod
    def _decode(cls, **kwargs):
        """
        Decode a connection error message.

        :param bytes payload: The connection error message.

        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the
                  connection error message class.
        :rtype: ``ConnectionError``
        """

        # Extract the error code
        error, = cls._error.unpack(kwargs['payload'][:cls._error.size])

        # Extract the error arguments
        error_payload = kwargs['payload'][cls._error.size:]
        arg_dec = cls._args.get(error)
        if arg_dec:
            args = arg_dec.type_(*arg_dec.struct.unpack(error_payload))
        else:
            args = None

        # Make and return the message object
        return cls(error, args, **kwargs)

    def __init__(self, error=0, args=None, **kwargs):
        """
        Initialize a ``ConnectionError`` instance.

        :param error: The error code.
        :param args: Additional arguments associated with the error.
        :param **kwargs: Additional keyword arguments to use for
                         initializing the ``Message`` portion.
        """

        # Initialize the Message
        super(ConnectionError, self).__init__(**kwargs)

        # Save the data
        self.error = error
        self.args = args

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        # Convert the error code first
        payload = self._error.pack(int(self.error))

        # Do we have an argument encoder?
        arg_enc = self._args.get(int(self.error))
        if arg_enc is None:
            return payload

        # Encode the arguments and return the assembled payload
        return payload + arg_enc[1].pack(*self.args)

    @attrs.FilterAttr
    def args(self, args):
        """
        The error arguments.  This will be a ``namedtuple`` specific to
        the error code.
        """

        # Allow args to be set to None
        if args is None:
            return None

        # If there's no encoder, arguments must be None
        arg_enc = self._args.get(int(self.error))
        if arg_enc is None:
            return None

        # Convert to the appropriate type
        if not isinstance(args, arg_enc.type_):
            return arg_enc.type_(*args)

        # No conversion necessary
        return args


def _protocol0(**kwargs):
    """
    Decode protocol 0 messages.

    :param carrier_flags: The carrier protocol flags.

    :returns: An appropriate instance of a subclass of ``Message``
              representing the protocol 0 message.
    :rtype: ``Message``
    """

    # Handle error and reply flags
    if 'error' in kwargs['carrier_flags']:
        return ConnectionError._decode(**kwargs)
    elif 'reply' in kwargs['carrier_flags']:
        return ConnectionState._decode(**kwargs)

    # Requests are simple, so there's no additional decoding to do
    return RequestConnectionState(**kwargs)
