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

import six

from hum_proto import attrs
from hum_proto import message


class SASLError(message.Message):
    """
    Represent a SASL error.
    """

    PROTOCOL = 3
    default_carrier_flags = 'error'

    # Attributes specific to this message type to display
    MSG_ATTRS = collections.OrderedDict([
        ('msg', six.text_type),
    ])

    @classmethod
    def _decode(cls, **kwargs):
        """
        Decode a SASL error message.

        :param bytes payload: The SASL error message.
        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the SASL
                  error message class.
        :rtype: ``SASLError``
        """

        # Extract the message
        msg = kwargs['payload'].decode('utf-8')

        return cls(msg, **kwargs)

    def __init__(self, msg, **kwargs):
        """
        Initialize a ``SASLError`` instance.

        :param msg: The error message.
        :param **kwargs: Additional keyword arguments to use for
                         initializing the ``Message`` portion.
        """

        # Initialize the Message
        super(SASLError, self).__init__(**kwargs)

        # Save the data
        self.msg = msg

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        return self.msg.encode('utf-8')

    @attrs.FilterAttr
    def msg(self, msg):
        """
        The error message.  This will be a string.
        """

        # Ensure the message is a string
        if not isinstance(msg, six.string_types):
            raise ValueError('Message must be a string')

        return msg


class RequestSASLMechanisms(message.Message):
    """
    Request a list of available SASL mechanisms.
    """

    PROTOCOL = 3

    @classmethod
    def _decode(cls, mechlen, **kwargs):
        """
        Decode a SASL mechanism list request.

        :param int mechlen: The size of the mechanism name.  This will
                            always be 255 and is ignored.
        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the SASL
                  mechanism list request.
        :rtype: ``RequestSASLMechanisms``
        """

        return cls(**kwargs)

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        return b'\xff'


class SASLMechanisms(message.Message):
    """
    Represent a list of SASL mechanisms.
    """

    PROTOCOL = 3
    default_carrier_flags = 'reply'

    # Attributes specific to this message type to display
    MSG_ATTRS = collections.OrderedDict([
        ('mechs', message.splitter),
    ])

    @classmethod
    def _decode(cls, mechlen, **kwargs):
        """
        Decode a SASL mechanism list.

        :param int mechlen: The size of the mechanism name.  This will
                            always be 255 and is ignored.
        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the SASL
                  mechanism list.
        :rtype: ``SASLMechanisms``
        """

        # Split the list of mechanisms
        mechs = kwargs['payload'][1:].split()

        return cls(mechs, **kwargs)

    def __init__(self, mechs, **kwargs):
        """
        Initialize a ``SASLMechanisms`` instance.

        :param mechs: A list of mechanism names, expressed as
                      ``bytes`` objects.
        """

        # Initialize the Message
        super(SASLMechanisms, self).__init__(**kwargs)

        # Save the data
        self.mechs = mechs

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        return b'\xff' + b' '.join(self.mechs)

    @attrs.FilterAttr
    def mechs(self, mechs):
        """
        The mechanisms.  This will be a list of ``bytes`` objects.
        """

        # Ensure the message is a list of bytes objects
        if not isinstance(mechs, list) or not all(
                isinstance(mech, bytes) for mech in mechs
        ):
            raise ValueError('Mechanisms list must be a list of bytes objects')

        # Uppercase the mechanims, for convenience
        return [m.upper() for m in mechs]


class SASLClientStep(message.Message):
    """
    Represent the client step in a SASL exchange.
    """

    PROTOCOL = 3

    # Struct for collecting the mechanism name length
    _mechlen = struct.Struct('>B')

    # Attributes specific to this message type to display
    MSG_ATTRS = collections.OrderedDict([
        ('mech', message.byter),
        ('data', message.byter),
    ])

    @classmethod
    def _decode(cls, mechlen, **kwargs):
        """
        Decode a SASL client step.

        :param int mechlen: The length of the mechanism name.
        :param bytes payload: The message payload, containing the
                              mechanism length, the mechanism name,
                              and the client data.
        :param **kwargs: Other keyword arguments to pass to the
                         constructor.

        :returns: An appropriately initialized instance of the SASL
                  client step class.
        :rtype: ``SASLClientStep``
        """

        # Extract the mechanism name, if any
        if mechlen:
            mech_end = cls._mechlen.size + mechlen
            mech = kwargs['payload'][cls._mechlen.size:mech_end]
        else:
            mech_end = cls._mechlen.size
            mech = None

        # Now extract the data
        data = kwargs['payload'][mech_end:]

        return cls(mech, data, **kwargs)

    def __init__(self, mech=None, data=None, **kwargs):
        """
        Initialize a ``SASLClientStep`` instance.

        :param mech: The mechanism name.
        :param data: The initial data for the SASL exchange.
        :param **kwargs: Additional keyword arguments to use for
                         initializing the ``Message`` portion.
        """

        # Initialize the Message
        super(SASLClientStep, self).__init__(**kwargs)

        # Save the data
        self.mech = mech
        self.data = data

    def _encode(self):
        """
        Assemble the payload.  The payload will be appended to the carrier
        protocol header to produce a complete protocol message.

        :returns: The assembled payload.
        :rtype: ``bytes``
        """

        # If we have a mechanism, include it
        if self.mech:
            return self._mechlen.pack(len(self.mech)) + self.mech + self.data

        # No mechanism name to include
        return self._mechlen.pack(0) + self.data

    @attrs.FilterAttr
    def mech(self, mech):
        """
        The mechanism name.  This will be a ``bytes`` object or ``None``.
        """

        # Ensure the mechanism name is bytes or None
        if mech is not None and not isinstance(mech, bytes):
            raise ValueError('Mechanism name must be bytes')

        return None if mech is None else mech.upper()

    @attrs.FilterAttr
    def data(self, data):
        """
        The step data.  This will be a ``bytes`` object or ``None``.
        """

        # Ensure the data is bytes or None
        if data is not None and not isinstance(data, bytes):
            raise ValueError('Mechanism data must be bytes')

        return data or b''


class SASLServerStep(SASLClientStep):
    """
    Represent the server step in a SASL exchange.
    """

    # Only difference with SASLClientStep is the reply flag
    default_carrier_flags = 'reply'


def _protocol3(**kwargs):
    """
    Decode protocol 3 messages.

    :param carrier_flags: The carrier protocol flags.
    :param bytes payload: The message payload.

    :returns: An appropriate instance of a subclass of ``Message``
              representing the protocol 3 message.
    :rtype: ``Message``
    """

    # Handle error messages
    if 'error' in kwargs['carrier_flags']:
        return SASLError._decode(**kwargs)

    # OK, extract the mechanism name length
    mechlen = SASLClientStep._mechlen.unpack(
        kwargs['payload'][:SASLClientStep._mechlen.size]
    )[0]

    # Handle the special case of mechanism name list
    if mechlen == 255:
        cls = (
            SASLMechanisms if 'reply' in kwargs['carrier_flags']
            else RequestSASLMechanisms
        )
    else:
        cls = (
            SASLServerStep if 'reply' in kwargs['carrier_flags']
            else SASLClientStep
        )

    # Hand the message off to the class for further decoding
    return cls._decode(mechlen, **kwargs)
