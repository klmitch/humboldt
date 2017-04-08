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

import six

from hum_proto import attrs
from hum_proto import enum


def _recvall(sock, size):
    """
    Read exactly the specified amount of data from a socket.  If a
    ``recv()`` call returns less than the requested amount, the
    ``recv()`` is retried until it either returns EOF or all the
    requested data has been read.

    :param sock: A socket from which bytes may be read.
    :param int size: The amount of data to read from the socket.

    :returns: The requested data.
    """

    data = b''

    while len(data) < size:
        buf = sock.recv(size - len(data))

        # Break out if we got an EOF
        if not buf:
            # Return None for an EOF
            return data or None

        data += buf

    return data


@six.add_metaclass(attrs.InvalidatingAttrMeta)
class Message(object):
    """
    Represent a protocol message.
    """

    # Registered and recognized protocols
    _decoders = {}

    # Information related to the carrier protocol
    _carrier_default_version = 0
    _carrier = struct.Struct('>BBH')
    _carrier_attrs = ['carrier_version', 'carrier_flags', 'protocol']

    # Attributes specific to this message type to display
    MSG_ATTRS = ['payload']

    # Carrier protocol flags
    carrier_flags = enum.FlagSetAttr(enum.EnumSet(
        enum.Enum('reply', 0x8, True),
        enum.Enum('error', 0x4, True),
    ), '_invalidate_bytes')

    @classmethod
    def register(cls, proto):
        """
        A decorator used to register a function to be used to decode a
        given protocol.  The function must take a carrier protocol
        version (``carrier_version``), carrier protocol flags
        (``carrier_flags``), the protocol number (``protocol``), the
        payload (``payload``), and the message bytes (``_bytes``) as
        keyword arguments, and must return an instance of a subclass
        of ``Message``.  (The recommended way of handling this is take
        arbitrary keyword arguments and pass them on to the
        ``Message`` constructor.)

        :param int proto: The protocol implemented by the class.

        :returns: A decorator that will register the decoder function.

        :raises TypeError:
            The protocol specified is invalid or already registered.
        """

        # Make sure protocol number makes sense
        if proto < 0 or proto > 255 or proto in cls._decoders:
            raise TypeError('Bad or duplicate protocol %d' % proto)

        # Decorator to actually register the class
        def decorator(decoder):
            cls._decoders[proto] = decoder

            return decoder

        return decorator

    @classmethod
    def recv(cls, sock):
        """
        Get the next message from a socket.

        :param sock: A socket from which bytes may be read.

        :returns: A ``Message`` instance, or an instance of an
                  appropriate ``Message`` subclass.
        """

        # First, get the carrier protocol header
        hdr = _recvall(sock, cls._carrier.size)
        if len(hdr) < cls._carrier.size:
            # No more data to read
            return None
        vers_flags, protocol, size = cls._carrier.unpack(hdr)
        version = (vers_flags >> 4) & 0xf
        flags = cls.carrier_flags.eset.flagset(vers_flags & 0xf)

        # Now we know how much else to get
        if size > cls._carrier.size:
            payload = _recvall(sock, size - cls._carrier.size)

            if len(payload) < size - cls._carrier.size:
                # Connection closed with incomplete frame
                return None
        else:
            payload = b''

        # Prepare the message parameters
        params = {
            'carrier_version': version,
            'carrier_flags': flags,
            'protocol': protocol,
            'payload': payload,
            '_bytes': hdr + payload,
        }

        # Make the message object
        obj = (cls._decoders[protocol]
               if protocol in cls._decoders else cls)(**params)

        return obj

    def __init__(self, carrier_version=None, carrier_flags=None,
                 protocol=None, payload=None, _bytes=None):
        """
        Initialize a ``Message`` instance.

        :param int carrier_version: The carrier protocol version.
        :param carrier_flags: The carrier protocol flags.
        :param int protocol: The protocol identifier from the carrier
                             protocol.
        :param bytes payload: The message payload.
        :param bytes _bytes: The full message bytes, including both
                             the carrier protocol header and the
                             payload.
        """

        # Save all the carrier protocol data
        self._carrier_version = carrier_version
        self.carrier_flags = carrier_flags
        self._protocol = protocol
        self._payload = payload
        self._bytes = _bytes

    def __len__(self):
        """
        Return the total length of the message, in bytes.

        :returns: The length of the message.
        :rtype: ``int``
        """

        return len(self.bytes)

    def __repr__(self):
        """
        Return a representation of this message value.

        :returns: A representation including all message attributes.
        :rtype: ``str``
        """

        # Assemble the attribute values
        values = ', '.join('%s=%r' % (attr, getattr(self, attr, None))
                           for attr in self._carrier_attrs + self.MSG_ATTRS)

        return '<%s size=%d, %s>' % (self.__class__.__name__,
                                     len(self), values)

    def _invalidate_bytes(self):
        """
        Bytes invalidation.  This is called if the carrier protocol flags
        are altered.
        """

        self._bytes = None

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.  This
        implementation returns an empty byte string.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        return b''

    def invalidate(self):
        """
        Payload invalidation.  This should be called if an attribute that
        contributes to the bytes representation of the message is
        altered.  It will invalidate both the ``payload`` property and
        the ``bytes`` property, ensuring that they will be recomputed
        if needed.
        """

        self._payload = None
        self._bytes = None

    def send(self, sock):
        """
        Encode the message to a sock.

        :param sock: A sock to which bytes may be written.
        """

        sock.sendall(self.bytes)

    @property
    def carrier_version(self):
        """
        Retrieve the carrier protocol version.
        """

        return (self._carrier_default_version if self._carrier_version is None
                else self._carrier_version)

    @property
    def protocol(self):
        """
        Retrieve the protocol number for the message.
        """

        return (getattr(self, 'PROTOCOL', 0)
                if self._protocol is None else self._protocol)

    @property
    def payload(self):
        """
        Retrieve the message payload.  This property calls the
        ``_encode()`` method, which should be overridden by subclasses
        to compute the bytes value of a message, excluding the carrier
        protocol header.
        """

        # Only call _encode() if the value isn't cached
        if self._payload is None:
            self._payload = self._encode()

        return self._payload

    @property
    def bytes(self):
        """
        Retrieve a bytes representation of this message.  This includes
        the carrier protocol header, and is suitable for sending to an
        output sock.
        """

        if self._bytes is None:
            # Reassemble version and flags
            vers_flags = (((self.carrier_version & 0xf) << 4) |
                          int(self.carrier_flags))

            # Grab the payload
            payload = self.payload

            # Determine the total size
            size = len(payload) + self._carrier.size

            # And assemble the bytes
            self._bytes = self._carrier.pack(vers_flags, self.protocol,
                                             size) + payload

        return self._bytes


class ConnectionState(Message):
    """
    Represent a connection state message.
    """

    # A struct format describing the contents of a connection state
    # reply
    _message = struct.Struct('>BB2x16s')

    # Attributes specific to this message type to display
    MSG_ATTRS = ['flags', 'status', 'node_id']

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


class RequestConnectionState(Message):
    """
    Represent a request for connection state message.  This message
    has no payload.
    """

    pass


# A named tuple for metadata about error codes
ErrorData = collections.namedtuple('ErrorData', ['type_', 'struct'])


class ConnectionError(Message):
    """
    Represent a connection error message.
    """

    # Structs and types for collecting the error code and decoding the
    # error arguments
    _error = struct.Struct('>B')
    _args = {
        0: None,
        1: ErrorData(
            collections.namedtuple('UnknownProtocol', ['protocol']),
            struct.Struct('>B'),
        ),
    }

    # Recognized error codes
    error = enum.EnumSet(
        enum.Enum('no error', 0),
        enum.Enum('unknown protocol', 1),
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


@Message.register(0)
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
