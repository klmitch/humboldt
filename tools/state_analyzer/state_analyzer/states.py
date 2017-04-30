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
from state_analyzer import transitions as trans


@six.add_metaclass(abc.ABCMeta)
class State(object):
    """
    Abstract base class for all states.  States must provide a
    ``name`` property, giving a string name for the state; a ``data``
    property, which provides data for serialization to YAML (and which
    may raise ``state_analyzer.common.Synthetic`` for synthetic
    states); and a ``dot`` property, which provides the representation
    of the state which is acceptable as node input for the GraphViz
    package.  They must also provide a ``_state_key()`` class method,
    which will receive a dictionary of arguments--which may be
    modified--and must return a hashable object which will be used as
    a dictionary key.  They must also provide a ``_state_init()``
    instance method, which will receive keyword arguments (as modified
    by ``_state_key()``), and must initialize the state instance.
    Note that ``State`` subclasses MUST NOT have an ``__init__()``
    method.
    """

    # Storage for all states
    _statedb = {}

    @classmethod
    def states(cls, state_class=None):
        """
        Obtain a list of states of a given type, sorted by the state name.

        :param state_class: The class of states to return.  If not
                            provided, defaults to the class the method
                            is called on.  This uses an
                            ``isinstance()`` test, so this argument
                            can be a tuple or a superclass.

        :returns: A list of the desired states, in order by the
                  state's name.
        :rtype: ``list`` of ``State``
        """

        # Return a sorted list of the states, sorting by name
        return sorted(
            (st for st in cls._statedb.values()
             if isinstance(st, state_class or cls)),
            key=lambda x: x.name,
        )

    def __new__(cls, **kwargs):
        """
        Obtain a ``State`` instance.  States are singleton classes: there
        can only be one state of a given description.  This method
        searches a database of states for states matching the
        description contained in ``kwargs``, creating and initializing
        a new one if needed.

        :param **kwargs: Keyword arguments describing the state.

        :returns: A corresponding ``State`` instance matching the
                  description.
        """

        # Obtain a hashable key for described state
        key = cls._state_key(kwargs)

        # Is it in the state database?
        if key not in cls._statedb:
            # Create a new one
            obj = super(State, cls).__new__(cls)

            # Initialize the object
            obj.key = key
            obj.transitions = []
            obj._state_init(**kwargs)

            # Save it
            cls._statedb[key] = obj

        # Return the state
        return cls._statedb[key]

    @abc.abstractmethod
    def _state_key(cls, kwargs):
        """
        Given a dictionary describing a state, compute and return an
        object suitable for use as a dictionary key.

        :param dict kwargs: Dictionary of keyword arguments passed to
                            the constructor.  This may be modified for
                            the benefit of a possible later call to
                            ``_state_init()``.

        :returns: A hashable object suitable for use as a dictionary
                  key.
        """

        pass  # pragma: no cover

    @abc.abstractmethod
    def _state_init(self, **kwargs):
        """
        Initialize a ``State`` instance.  Subclasses MUST implement this
        method in lieu of an ``__init__()`` method, which MUST NOT be
        implemented (as ``__init__()`` could be called on an already
        initialized instance).

        :param **kwargs: Keyword arguments passed to the constructor,
                         as optionally modified by ``_state_key()``.
        """

        pass  # pragma: no cover

    @abc.abstractproperty
    def name(self):
        """
        A textual name for the state.
        """

        pass  # pragma: no cover

    @abc.abstractproperty
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``State`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the state is a synthetic state that does
            not need to be serialized to a YAML representation.
        """

        pass  # pragma: no cover

    @abc.abstractproperty
    def dot(self):
        """
        A string which provides the representation of the state which is
        acceptable as node input for the GraphViz package.
        """

        pass  # pragma: no cover


class StartState(State):
    """
    Represents a "start" state.  Start states precede Humboldt states
    and provide an anonymous arrow pointing in to the corresponding
    Humboldt start state.
    """

    @classmethod
    def _state_key(cls, kwargs):
        """
        Given a dictionary describing a state, compute and return an
        object suitable for use as a dictionary key.

        :param dict kwargs: Dictionary of keyword arguments passed to
                            the constructor.  This may be modified for
                            the benefit of a possible later call to
                            ``_state_init()``.

        :returns: A hashable object suitable for use as a dictionary
                  key.
        """

        return id(kwargs['target'])

    def _state_init(self, target, group, send=False):
        """
        Initialize a ``State`` instance.  Subclasses MUST implement this
        method in lieu of an ``__init__()`` method, which MUST NOT be
        implemented (as ``__init__()`` could be called on an already
        initialized instance).

        :param target: The target of the transition from the start
                       state.  This will be a ``HumboldtState`` marked
                       as a start state.
        :type target: ``HumboldtState``
        :param str group: The start state group.
        :param bool send: Whether the starting connection state should
                          be communicated to the other end of the
                          connection.  Defaults to ``False``.
        """

        self.target = target
        self.group = group
        self.transitions.append(trans.StartTransition(self, target, send))

    @common.CachedProperty
    def name(self):
        """
        A textual name for the state.
        """

        return 'start%03d' % self.target.seq

    @property
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``State`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the state is a synthetic state that does
            not need to be serialized to a YAML representation.
        """

        raise common.Synthetic()

    @common.CachedProperty
    def dot(self):
        """
        A string which provides the representation of the state which is
        acceptable as node input for the GraphViz package.
        """

        return '"%s" [shape=none,label=""];' % self.name


class HumboldtState(State):
    """
    Represents a state that Humboldt may be in.  These states are
    primarily composed of a set of state flags and a status code, as
    well as a connection mode which is never communicated to the other
    end of a connection.  Additional properties include flags
    indicating whether the state is a start state (``start``) or an
    acceptance state (``accept``).  Acceptance states indicate states
    where the connection is fully authenticated and secured.
    """

    # Used to assign sequential indices to states
    _cnt = 0
    _cnt_used = set()

    @classmethod
    def _state_key(cls, kwargs):
        """
        Given a dictionary describing a state, compute and return an
        object suitable for use as a dictionary key.  This
        implementation canonicalizes the ``flags`` keyword argument to
        a ``frozenset``, as it is a component of the hashable key.

        :param dict kwargs: Dictionary of keyword arguments passed to
                            the constructor.  This may be modified for
                            the benefit of a possible later call to
                            ``_state_init()``.

        :returns: A hashable object suitable for use as a dictionary
                  key.
        """

        # Canonicalize flags
        kwargs['flags'] = set(kwargs['flags'])

        # Return a hashable key
        return (kwargs['mode'], frozenset(kwargs['flags']), kwargs['status'])

    def _state_init(self, mode, flags, status, **kwargs):
        """
        Initialize a ``State`` instance.  Subclasses MUST implement this
        method in lieu of an ``__init__()`` method, which MUST NOT be
        implemented (as ``__init__()`` could be called on an already
        initialized instance).

        :param str mode: The connection mode.
        :param frozenset flags: The connection flags.
        :param str status: The connection status.

        :param **kwargs: Additional keyword arguments passed to the
                         constructor, as optionally modified by
                         ``_state_key()``.  These are generally
                         keyword arguments intended for the
                         ``configure()`` method.
        """

        self.mode = mode
        self.flags = flags
        self.status = status
        self.start = False
        self.start_send = False
        self.accept = False

    def configure(self, start=None, start_send=None, accept=None,
                  transitions=None, seq=None, **kwargs):
        """
        Used to configure a state after initialization.  This ensures that
        state references within transitions cannot alter certain
        canonical properties, such as whether the state is a start
        state, while still ensuring that forward references to a state
        work.

        :param str start: The start state group.  If not provided, the
                          state is considered not to be a start state.
        :param bool start_send: Whether the starting state should be
                                sent to the other end of the
                                connection when the state is entered.
                                If not provided, the default
                                (``False``) is preserved.
        :param bool accept: Whether the state is an accepting state.
                            If not provided, the default (``False``)
                            is preserved.
        :param transitions: A list of transitions.  Each element of
                            the list must be a dictionary acceptable
                            for use as keyword arguments to the
                            ``state_analyzer.transitions.HumboldtTransition``
                            constructor.
        :type transitions: ``list`` of ``dict``
        :param int seq: An integer sequence number to assign to the
                        state.  If not provided, one will be
                        automatically assigned based on a counter.

        :param **kwargs: Additional keyword arguments passed to the
                         method.  These are generally keyword
                         arguments intended for the constructor.
        """

        # Assign a sequence number
        if seq is not None and seq not in self._cnt_used:
            self.seq = seq
            self._cnt_used.add(seq)
        else:
            # Use an automatically assigned sequence number
            seq = self.seq

        # Set the start and accept flags
        if start is not None:
            self.start = start
        if start_send is not None:
            self.start_send = start_send
        if accept is not None:
            self.accept = accept

        # Set up the transitions
        if transitions:
            for tr_data in transitions:
                self.transitions.append(
                    trans.HumboldtTransition(self, **tr_data)
                )

        # Set up the start state as well
        if self.start:
            StartState(target=self, group=self.start, send=self.start_send)

        # Clear the caches
        del self.data
        del self.dot

    @common.CachedProperty
    def seq(self):
        """
        Obtain the state's sequence number.  Sequence numbers are lazy
        binding to ensure that the sequence number corresponds to the
        list index.
        """

        # Look for a free sequence number
        while self.__class__._cnt in self._cnt_used:
            self.__class__._cnt += 1

        # Assign the next available sequence number
        seq = self.__class__._cnt
        self._cnt_used.add(seq)

        # Increment for the next sequence assignment
        self.__class__._cnt += 1

        return seq

    @common.CachedProperty
    def name(self):
        """
        A textual name for the state.
        """

        return 'state%03d' % self.seq

    @common.CachedProperty
    def basic_data(self):
        """
        A dictionary suitable for serialization to an input file.  This
        must contain only the basic data about the state.  This is
        extended by the ``data`` property, but used directly by the
        ``state_analyzer.transitions.HumboldtTransition.data``
        property.
        """

        return collections.OrderedDict([
            ('seq', self.seq),
            ('mode', self.mode),
            ('flags', self.flags),
            ('status', self.status),
        ])

    @common.CachedProperty
    def data(self):
        """
        A dictionary suitable for serialization to an input file.  It must
        be possible to use this dictionary as keyword arguments for a
        ``State`` constructor.

        :raises state_analyzer.common.Synthetic:
            May be raised if the state is a synthetic state that does
            not need to be serialized to a YAML representation.
        """

        data = self.basic_data.copy()

        if self.start:
            data['start'] = self.start
        if self.start_send:
            data['start_send'] = self.start_send
        if self.accept:
            data['accept'] = self.accept
        if self.transitions:
            data['transitions'] = []
            for tr in self.transitions:
                try:
                    data['transitions'].append(tr.data)
                except common.Synthetic:
                    pass

        return data

    @common.CachedProperty
    def dot(self):
        """
        A string which provides the representation of the state which is
        acceptable as node input for the GraphViz package.
        """

        return (
            '"%(name)s" [style=filled,label=<'
            '<table bgcolor="white">'
            '<tr>'
            '<td align="center" colspan="2" bgcolor="black">'
            '<font color="white"><b>%(seq)d</b></font>'
            '</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Mode</b></td>'
            '<td align="left">%(mode)s</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Flags</b></td>'
            '<td align="left">%(flags)s</td>'
            '</tr>'
            '<tr>'
            '<td align="right"><b>Status</b></td>'
            '<td align="left">%(status)s</td>'
            '</tr>'
            '</table>'
            '>%(peripheries)s];'
        ) % {
            'seq': self.seq,
            'name': self.name,
            'mode': self.mode,
            'flags': ', '.join(sorted(self.flags)),
            'status': self.status,
            'peripheries': ',peripheries=2' if self.accept else '',
        }
