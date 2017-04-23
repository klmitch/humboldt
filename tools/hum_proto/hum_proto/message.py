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
import itertools
import struct

import entrypointer
import six

from hum_proto import attrs
from hum_proto import enum


def flagger(value):
    """
    Conversion routine for flags.  Accepts ints or comma-separated
    strings.

    :param str value: The value to convert.

    :returns: A value of an appropriate type.
    """

    try:
        # Convert as an integer
        return int(value)
    except ValueError:
        # Convert as a comma-separated list
        return [v.strip() for v in value.split(',')]


def enumer(value):
    """
    Conversion routine for enumeration values.  Accepts ints or
    strings.

    :param str value: The value to convert.

    :returns: A value of an appropriate type.
    """

    try:
        # Convert as an integer
        return int(value)
    except ValueError:
        # Return the string unchanged
        return value


# Simple escape sequences for _byter()
_escapes = {
    "'": ord("'"),
    '"': ord('"'),
    'a': ord('\a'),
    'b': ord('\b'),
    'f': ord('\f'),
    'n': ord('\n'),
    'r': ord('\r'),
    't': ord('\t'),
    'v': ord('\v'),
}


def byter(value):
    """
    Conversion routine for bytes values.  Converts a value to a bytes
    literal.  This interprets escapes similarly to how Python does it,
    with a little more strictness with respect to octal escapes.

    :param str value: The value to convert.

    :returns: A bytes value.
    :rtype: ``bytes``
    """

    # Have to build this up manually, possibly from integers
    result = bytearray()

    # Split on backslashes
    last_empty = False
    for i, part in enumerate(value.split('\\')):
        escape = i > 0

        # Look out for doubled escapes
        if last_empty:
            result.append(ord('\\'))
            last_empty = False
            escape = False
        elif escape and not part:
            last_empty = True
            continue

        pos = 0
        if escape:
            # Handle the escape sequence
            if part[pos] in _escapes:
                # Simple escape sequence
                result.append(_escapes[part[pos]])
                pos += 1
            elif part[pos] == 'x':
                # Hexadecimal escape sequence
                if len(part) < 3:
                    raise ValueError('Invalid \\x escape')
                result.append(int(part[1:3], 16))
                pos += 3
            elif '0' <= part[pos] <= '7':
                # Octal escape sequence
                c = 0
                while pos < min(3, len(part)) and '0' <= part[pos] <= '7':
                    # Check if this would cause an overflow
                    if ((c << 3) | int(part[pos], 8)) > 255:
                        break

                    # Update
                    c = (c << 3) | int(part[pos], 8)
                    pos += 1

                result.append(c)
            else:
                # Unrecognized escape
                result.append(ord('\\'))

        # Add the rest of the part
        result += bytearray(ord(c) for c in part[pos:])

    return bytes(result)


def splitter(value):
    """
    Conversion routine for lists.  Accepts comma-separated strings.

    :param str value: The value to convert.

    :returns: A list of strings.
    :rtype: ``list``
    """

    return [v.strip() for v in value.split(',')]


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


class CommandError(Exception):
    """
    Represents errors in commands.
    """

    pass


@six.add_metaclass(attrs.InvalidatingAttrMeta)
class Message(object):
    """
    Represent a protocol message.
    """

    # Recognized classes and protocol decoders
    _classes = entrypointer.eps.hum_proto.msg
    _decoders = entrypointer.eps.hum_proto.proto

    # Information related to the carrier protocol
    _carrier_default_version = 0
    _carrier = struct.Struct('>BBH')
    _carrier_attrs = collections.OrderedDict([
        ('carrier_version', int),
        ('carrier_flags', flagger),
        ('protocol', int),
    ])

    # Attributes specific to this message type to display
    MSG_ATTRS = collections.OrderedDict([
        ('payload', byter),
    ])

    # Carrier protocol flags
    carrier_flags = enum.FlagSetAttr(enum.EnumSet(
        enum.Enum('reply', 0x8, True),
        enum.Enum('error', 0x4, True),
    ), '_invalidate_bytes')

    # Default carrier protocol flags for this class
    default_carrier_flags = None

    # Optional method that allows an action to be taken when a message
    # is sent.  The method will be passed the application loop object.
    action = None

    # Optional method that allows an action to be taken when a message
    # is received.  The method will be passed the application loop
    # object.
    reaction = None

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
        if not hdr or len(hdr) < cls._carrier.size:
            # No more data to read
            return None
        vers_flags, protocol, size = cls._carrier.unpack(hdr)
        version = (vers_flags >> 4) & 0xf
        flags = cls.carrier_flags.eset.flagset(vers_flags & 0xf)

        # Now we know how much else to get
        if size > cls._carrier.size:
            payload = _recvall(sock, size - cls._carrier.size)

            if not payload or len(payload) < size - cls._carrier.size:
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
        obj = (cls._decoders[str(protocol)]
               if str(protocol) in cls._decoders else cls)(**params)

        return obj

    @classmethod
    def interpret(cls, command):
        """
        Interpret a list of command tokens.  The first tokens are taken to
        name the message type, which should be followed by tokens of
        the form "param=value".  The "param" should be the name of a
        recognized message parameter, and the "value" should be an
        appropriate value for that parameter.

        :param list command: The list of command tokens to interpret.

        :returns: An instance of an appropriate ``Message`` subclass
                  representing the desired value.
        :rtype: ``Message``
        """

        # Figure out which tokens compose the message type
        for i in range(len(command)):
            if '=' in command[i]:
                type_name = ''.join(command[:i])
                command = command[i:]
                break
        else:
            type_name = ''.join(command)
            command = []

        # Look up the message type
        type_ = cls._classes.get(type_name.lower())
        if type_ is None:
            raise CommandError('Unknown message type "%s"' % type_name)

        # Now interpret the tokens
        params = {}
        for tok in command:
            key, sep, value = tok.partition('=')
            if not sep:
                raise CommandError(
                    'No value for parameter "%s" for message type %s' %
                    (key, type_.__name__)
                )
            elif (key not in type_._carrier_attrs and
                  key not in type_.MSG_ATTRS):
                raise CommandError(
                    'Unknown parameter "%s" for message type %s' %
                    (key, type_.__name__)
                )

            # Save the value
            try:
                if key in type_._carrier_attrs:
                    params[key] = type_._carrier_attrs[key](value)
                else:
                    params[key] = type_.MSG_ATTRS[key](value)
            except Exception as err:
                raise CommandError(
                    'Bad value "%s" for parameter "%s" (message type %s): %s' %
                    (value, key, type_.__name__, err)
                )

        # Create the message
        try:
            return type_(**params)
        except Exception as err:
            raise CommandError(
                'Unable to create requested message type %s: %s' %
                (type_.__name__, err)
            )

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
        self.carrier_flags = carrier_flags or self.default_carrier_flags
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
                           for attr in itertools.chain(self._carrier_attrs,
                                                       self.MSG_ATTRS))

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
