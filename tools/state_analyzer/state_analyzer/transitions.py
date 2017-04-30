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
import copy

import six

from state_analyzer import actions
from state_analyzer import common


@six.add_metaclass(abc.ABCMeta)
class Transition(object):
    """
    Abstract base class for all state transitions.  Transitions must
    provide a ``data`` property, which provides data for serialization
    to YAML (and which may raise ``state_analyzer.common.Synthetic``
    for synthetic transitions); and a ``dot`` property, which provides
    the representation of the transition which is acceptable as edge
    input for the GraphViz package.
    """

    @abc.abstractproperty
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``Transition`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the transition is a synthetic transition
            that does not need to be serialized to a YAML
            representation.
        """

        pass  # pragma: no cover

    @abc.abstractproperty
    def dot(self):
        """
        A string which provides the representation of the transition which
        is acceptable as edge input for the GraphViz package.
        """

        pass  # pragma: no cover


class StartTransition(Transition):
    """
    Represents a "start" transition.  Start states precede Humboldt
    states, and this class represents the transition (an anonymous
    arrow) pointing in to the corresponding Humboldt start state.
    """

    def __init__(self, origin, target, send=False):
        """
        Initialize a ``StartTransition`` instance.

        :param origin: The origin of the start transition.
        :type origin: ``state_analyzer.states.State``
        :param target: The target of the state transition.
        :type target: ``state_analyzer.states.State``
        :param bool send: Whether the starting connection state should
                          be communicated to the other end of the
                          connection.  Defaults to ``False``.
        """

        self.origin = origin
        self.target = target
        self.send = send

    @common.CachedProperty
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``Transition`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the transition is a synthetic transition
            that does not need to be serialized to a YAML
            representation.
        """

        raise common.Synthetic()

    @common.CachedProperty
    def dot(self):
        """
        A string which provides the representation of the transition which
        is acceptable as edge input for the GraphViz package.
        """

        return '"%(origin)s" -> "%(target)s" [color=%(color)s];' % {
            'origin': self.origin.name,
            'target': self.target.name,
            'color': 'red' if self.send else 'blue',
        }


class HumboldtTransition(Transition):
    """
    Represents a legal transition between states that Humboldt may be
    in.  These transitions may expect a certain condition, such as a
    function executed by the other side or the communication of a
    certain connection state, and they may also initiate actions.
    They may also be flagged as including a communication of the state
    being transitioned to; this transmission will occur before the
    transition action is invoked.  It is also possible to flag
    transitions where the expectation is not actually expected to
    occur.
    """

    def __init__(self, origin, expect=None, action=None, send=False,
                 expected=True, **kwargs):
        """
        Initialize a ``HumboldtTransition`` instance.

        :param origin: The origin of the state transition.
        :type origin: ``state_analyzer.states.State``
        :param expect: The expectation of the transition; this is an
                       event that must occur before the transition can
                       be taken.  Can be ``None`` to indicate that the
                       transition must occur as soon as the antecedent
                       state is entered; such states MUST have this
                       transition as the only transition.  Otherwise,
                       must be a ``str`` indicating a function that
                       must be completed, or ``dict`` to indicate the
                       communication of a state from the other end of
                       the connection.
        :param action: The action to be taken after making the
                       transition.  Can be ``None`` to indicate that
                       no action will be taken, or a ``str``
                       indicating a function that must be invoked.
        :param bool send: Whether the new state should be communicated
                          to the other end of the connection before
                          the action (if any) is invoked.  Defaults to
                          ``False``.
        :param bool expected: Whether the transition is actually
                              expected to occur.  If ``True``, the
                              transition is provided only because of
                              the maxim, "Be liberal in what you
                              accept."  This only results in the
                              transition being indicated visually as a
                              dashed line.
        :param **kwargs: Additional keyword arguments passed to the
                         constructor.  These are passed on to the
                         constructor for
                         ``state_analyzer.states.HumboldtState`` to
                         obtain the target state of the transition.
        """

        # Have to import here to break a circular dependency
        from state_analyzer import states

        self.origin = origin
        self.target = states.HumboldtState(**kwargs)
        self.expect = actions.make_action(expect)
        self.action = actions.make_action(action)
        self.send = send
        self.expected = expected

    @common.CachedProperty
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``Transition`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the transition is a synthetic transition
            that does not need to be serialized to a YAML
            representation.
        """

        # Get a copy of the target state
        data = copy.deepcopy(self.target.basic_data)

        # Add on the expect and action values
        data.update([
            ('expect', self.expect.data),
            ('action', self.action.data),
        ])

        # Add the flags
        if self.send:
            data['send'] = self.send
        if not self.expected:
            data['expected'] = self.expected

        return data

    @common.CachedProperty
    def dot(self):
        """
        A string which provides the representation of the transition which
        is acceptable as edge input for the GraphViz package.
        """

        return (
            '"%(origin)s" -> "%(target)s" [label=<'
            '<table>'
            '<tr>'
            '<td align="right"><b>Expected</b></td>'
            '<td align="left">%(expect)s</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Action</b></td>'
            '<td align="left">%(action)s</td>'
            '</tr>'
            '</table>'
            '>,color=%(color)s,style=%(style)s];'
        ) % {
            'origin': self.origin.name,
            'target': self.target.name,
            'expect': self.expect.dot,
            'action': self.action.dot,
            'color': 'red' if self.send else 'blue',
            'style': 'solid' if self.expected else 'dashed',
        }
