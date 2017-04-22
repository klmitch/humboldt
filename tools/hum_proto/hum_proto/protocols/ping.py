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


class PingReply(message.Message):
    """
    Represent a ping reply.
    """

    PROTOCOL = 1
    default_carrier_flags = 'reply'


class PingRequest(message.Message):
    """
    Represent a ping request.
    """

    PROTOCOL = 1

    def reaction(self, apploop):
        """
        A reaction is invoked when a message is received.  This reaction
        is designed to reply to a ping request with a corresponding
        ping reply.

        :param apploop: The application loop.
        :type apploop: ``hum_proto.apploop.ApplicationLoop``
        """

        # Generate a proper reply
        apploop.send_msg(PingReply(payload=self.payload))


def _protocol1(**kwargs):
    """
    Decode protocol 1 messages.

    :param carrier_flags: The carrier protocol flags.

    :returns: An appropriate instance of a subclass of ``Message``
              representing the protocol 1 message.
    :rtype: ``Message``
    """

    # Error flag isn't defined for protocol 1
    if 'error' in kwargs['carrier_flags']:
        return message.Message(**kwargs)
    elif 'reply' in kwargs['carrier_flags']:
        return PingReply(**kwargs)

    return PingRequest(**kwargs)
