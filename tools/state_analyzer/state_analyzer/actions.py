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

import abc
import collections

import six

from state_analyzer import common


@six.add_metaclass(abc.ABCMeta)
class Action(object):
    """
    Abstract base class for all state transition actions.  Actions
    must provide a ``data`` property, which provides data for
    serialization to YAML; and a ``dot`` property, which provides the
    representation of the action which is acceptable as a table cell
    entry in the label input for the GraphViz package.
    """

    @abc.abstractproperty
    def data(self):
        """
        An object suitable for serialization to an input file.  It must be
        possible to use this object as the argument for the
        ``make_action()`` function.
        """

        pass  # pragma: no cover

    @abc.abstractproperty
    def dot(self):
        """
        A string which provides the representation of the action which is
        acceptable as a table cell entry in the label input for the
        GraphViz package.
        """

        pass  # pragma: no cover


class NoneAction(Action):
    """
    An action used when the action provided is ``None``.
    """

    data = None
    dot = '<i>none</i>'


class ForeignStateAction(Action):
    """
    An action used to represent the expected state communication from
    the other end of a connection.
    """

    def __init__(self, flags, status):
        """
        Initialize a ``ForeignStateAction`` instance.

        :param flags: A list of the expected connection flags.
        :type flags: ``list`` of ``str``
        :param str status: The expected connection status.
        """

        # Canonicalize the flags the same way HumboldtState does
        self.flags = set(flags)
        self.status = status

    @common.CachedProperty
    def data(self):
        """
        An object suitable for serialization to an input file.  It must be
        possible to use this object as the argument for the
        ``make_action()`` function.
        """

        return collections.OrderedDict([
            ('flags', self.flags),
            ('status', self.status),
        ])

    @common.CachedProperty
    def dot(self):
        """
        A string which provides the representation of the action which is
        acceptable as a table cell entry in the label input for the
        GraphViz package.
        """

        return (
            '<table>'
            '<tr>'
            '<td align="right"><b>Flags</b></td>'
            '<td align="left">%(flags)s</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Status</b></td>'
            '<td align="left">%(status)s</td>'
            '</tr>'
            '</table>'
        ) % {
            'flags': ', '.join(sorted(self.flags)),
            'status': self.status,
        }


class FunctionAction(Action):
    """
    An action used to represent a function that it is expected the
    other end of a connection will invoke, or a function that is to be
    invoked after transition to the target state.
    """

    def __init__(self, function):
        """
        Initialize a ``FunctionAction`` instance.

        :param str function: The function to expect or invoke.
        """

        self.function = function

    @property
    def data(self):
        """
        An object suitable for serialization to an input file.  It must be
        possible to use this object as the argument for the
        ``make_action()`` function.
        """

        return self.function

    @property
    def dot(self):
        """
        A string which provides the representation of the action which is
        acceptable as a table cell entry in the label input for the
        GraphViz package.
        """

        return self.function


# Only need one of these NoneAction instances
none_action = NoneAction


def make_action(action):
    """
    Construct the correct ``Action`` instance for a given action
    representation.

    :param action: The action.  May be ``None``, a ``str``, or a
                   ``dict``.

    :returns: An appropriate action description.
    :rtype: ``Action``
    """

    if action is None:
        return none_action
    elif isinstance(action, dict):
        return ForeignStateAction(**action)
    else:
        return FunctionAction(action)
