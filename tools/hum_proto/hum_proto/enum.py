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
import functools

import six

from hum_proto import attrs


@functools.total_ordering
class Enum(object):
    """
    An enumeration item.  This is an object which has a string value
    and a corresponding integer value.
    """

    def __init__(self, name, value, makehex=False):
        """
        Initialize an ``Enum`` instance.

        :param str name: The string value of the enumeration.
        :param int value: The integer value of the enumeration.
        :param bool makehex: If ``True``, display the value in
                             hexadecimal when producing a
                             representation.
        """

        self.name = name
        self.value = value
        self.makehex = makehex

        # An EnumSet this is a member of
        self.eset = None

    def __repr__(self):
        """
        Return a representation of this enumeration value.

        :returns: A representation including both the name and value.
        :rtype: ``str``
        """

        return (('<%s "%s" (0x%x)>' if self.makehex else '<%s "%s" (%d)>') %
                (self.__class__.__name__, self.name, self.value))

    def __str__(self):
        """
        Return the string value of this enumeration value.

        :returns: The string value of this enumeration value.
        :rtype: ``str``
        """

        return self.name

    def __int__(self):
        """
        Return the integer value of this enumeration value.

        :returns: The integer value of this enumeration value.
        :rtype: ``int``
        """

        return self.value

    def __eq__(self, other):
        """
        Compare for equality.

        :param other: Another object to check for equality.  Can be a
                      string, an integer, or another enumeration
                      value.

        :returns: A ``True`` value if the objects are equal, ``False``
                  otherwise.
        :rtype: ``bool``
        """

        if isinstance(other, Enum):
            return self.name == other.name and self.value == other.value
        elif isinstance(other, six.integer_types):
            return self.value == other
        elif isinstance(other, six.string_types):
            return self.name == other

        return False

    def __ne__(self, other):
        """
        Compare for inequality.

        :param other: Another object to check for inequality.  Can be
                      a string, an integer, or another enumeration
                      value.

        :returns: A ``True`` value if the objects are not equal,
                  ``False`` otherwise.
        :rtype: ``bool``
        """

        if isinstance(other, Enum):
            return self.name != other.name or self.value != other.value
        elif isinstance(other, six.integer_types):
            return self.value != other
        elif isinstance(other, six.string_types):
            return self.name != other

        return True

    def __lt__(self, other):
        """
        Determine if this enumeration value is less than another
        enumeration value.

        :param other: Another object to compare to.  Can be a string,
                      an integer, or another enumeration value.
                      Comparisons are done by integer value.

        :returns: A ``True`` value if this enumeration value is less
                  than the other, or ``False`` otherwise.  Note that
                  ``NotImplemented`` may be returned if ``other`` is
                  an unrecognized type, or if ``other`` is a string
                  with no corresponding enumeration value.
        """

        if isinstance(other, Enum):
            return self.value < other.value
        elif isinstance(other, six.integer_types):
            return self.value < other
        elif isinstance(other, six.string_types):
            # Try using the EnumSet to map string to value
            if not self.eset or other not in self.eset.by_name:
                return NotImplemented
            return self.value < self.eset.by_name[other].value

        return NotImplemented


class EnumSet(object):
    """
    Describes a set of related ``Enum`` instances.
    """

    def __init__(self, *options):
        """
        Initialize an ``EnumSet`` instance.

        :param *options: A tuple of ``Enum`` instances.  Any field
                         having an ``EnumSet`` can take on only the
                         values specified by this tuple.
        """

        # Initialize the list of options
        self.opts = options

        # Build the indexes
        self.by_name = {}
        self.by_value = {}
        for opt in options:
            self.by_name[opt.name] = opt
            self.by_value[opt.value] = opt

            # Tell the enumeration that it's part of us; needed for
            # comparisons with strings
            opt.eset = self

    def __len__(self):
        """
        Determine the number of options contained within the ``EnumSet``
        instance.

        :returns: The total number of options.
        :rtype: ``int``
        """

        return len(self.by_value)

    def __iter__(self):
        """
        Iterate over the options contained within the ``EnumSet``
        instance.

        :returns: An iterator that yields each ``Enum`` in turn.
        """

        return iter(self.opts)

    def __contains__(self, value):
        """
        Determine if a given value is a valid value according to the
        ``EnumSet`` instance.

        :param value: The value to check, either an integer or a
                      string.

        :returns: A ``True`` value if ``value`` is valid, ``False``
                  otherwise.
        :rtype: ``bool``
        """

        try:
            # Just use __getitem__()
            self[value]
        except KeyError:
            return False
        else:
            return True

    def __getitem__(self, value):
        """
        Get the ``Enum`` instance that corresponds to a given value.

        :param value: The value in question, either an integer or a
                      string.

        :returns: The ``Enum`` instance corresponding to that value.

        :raises KeyError:
            The value does not have a corresponding ``Enum`` instance.
        """

        # Select the correct index
        if isinstance(value, six.integer_types):
            idx = self.by_value
        elif isinstance(value, six.string_types):
            idx = self.by_name
        else:
            raise KeyError(value)

        # Look up the value in that index
        return idx[value]

    def flagset(self, flags=None):
        """
        Construct a ``FlagSet`` from this ``EnumSet`` instance.

        :param flags: Flags from which to initialize the ``FlagSet``
                      instance.  May be either an integer, giving a
                      full bit flag; or a sequence of strings or
                      integers, which each must be members of this
                      ``EnumSet``.

        :returns: An appropriately constructed ``FlagSet`` instance.
        :rtype: ``FlagSet``
        """

        return FlagSet(self, flags)

    @property
    def attr(self):
        """
        Construct an ``EnumAttr`` from this ``EnumSet`` instance.

        :returns: An appropriately constructed ``EnumAttr`` instance.
        :rtype: ``EnumAttr``
        """

        return EnumAttr(self)

    @property
    def flags(self):
        """
        Construct a ``FlagSetAttr`` from this ``EnumSet`` instance.

        :returns: An appropriately constructed ``FlagSetAttr``
                  instance.
        :rtype: ``FlagSetAttr``
        """

        return FlagSetAttr(self)


class FlagSet(collections.MutableSet):
    """
    A ``set``-like object that tracks bit flags.
    """

    def __init__(self, eset, flags=None):
        """
        Initialize a ``FlagSet`` instance.

        :param eset: An ``EnumSet`` instance that contains the legal
                     bit flags that may be used.
        :param flags: Flags from which to initialize the ``FlagSet``
                      instance.  May be either an integer, giving a
                      full bit flag; or a sequence of strings or
                      integers, which each must be members of
                      ``eset``.

        :raises TypeError:
            One or more flags could not be converted.
        """

        # Store the EnumSet
        self.eset = eset

        # Initialize the flags
        self.bitflags = 0
        self.flags = set()

        # Routine to call if we're modified
        self._notify = None

        # Process the flags that were set
        if isinstance(flags, six.integer_types):
            for opt in eset:
                if flags & int(opt):
                    self.bitflags |= int(opt)
                    self.flags.add(str(opt))

            # Make sure we got them all
            if self.bitflags != flags:
                raise TypeError(
                    'Unable to find enumeration values for 0x%x' %
                    (flags & ~self.bitflags)
                )
        elif isinstance(flags, six.string_types):
            try:
                opt = eset[flags]
            except KeyError:
                raise TypeError(
                    'Unable to find enumeration value for flag \"%s\"' % flags
                )

            self.bitflags |= int(opt)
            self.flags.add(str(opt))
        elif flags is not None:
            for flag in flags:
                try:
                    opt = eset[flag]
                except KeyError:
                    raise TypeError(
                        'Unable to find enumeration value for flag \"%s\"' %
                        flag
                    )

                self.bitflags |= int(opt)
                self.flags.add(str(opt))

    def __repr__(self):
        """
        Return a representation of this flag set value.

        :returns: A representation including the set flags.
        :rtype: ``str``
        """

        flags = [str(flg) for flg in self.eset if str(flg) in self.flags]
        return ('<%s [%s] (0x%x)>' % (
            self.__class__.__name__, ', '.join(flags), self.bitflags))

    def __int__(self):
        """
        Returns the integer value of the ``FlagSet`` instance.

        :returns: The integer value of the ``FlagSet`` instance.
        :rtype: ``int``
        """

        return self.bitflags

    def __contains__(self, flag):
        """
        Determine if the ``FlagSet`` instance contains the specified
        flags.

        :param flag: The flag or sequence of flags to check.  May be
                     an integer, a string, or a sequence of integers
                     or strings (or ``Enum`` instances).

        :returns: A ``True`` value if all the specified flags are set
                  in the ``FlagSet`` instance, ``False`` otherwise.
        """

        if isinstance(flag, six.integer_types):
            # Pretty easy
            return (self.bitflags & flag) == flag
        elif isinstance(flag, six.string_types):
            # Simple string
            return flag in self.flags
        else:
            try:
                # Make sure all the specified flags are present
                return all(str(self.eset[fl]) in self.flags
                           for fl in flag)
            except KeyError:
                return False

    def __iter__(self):
        """
        Iterate over the flags contained within the ``FlagSet`` instance.

        :returns: An iterator that yields each ``Enum`` which
                  corresponds to a bit that is set.  The ``Enum``
                  instances will be in the same order as for the
                  ``EnumSet`` instance used to construct the
                  ``FlagSet`` instance.
        """

        for opt in self.eset:
            if self.bitflags & int(opt):
                yield opt

    def __len__(self):
        """
        Determine the number of flags set.

        :returns: The number of flags set.
        :rtype: ``int``
        """

        return len(self.flags)

    def add(self, flag):
        """
        Set a flag on the ``FlagSet`` instance.

        :param flag: The flag to set.  May be an integer, a string, or
                     an ``Enum`` instance.

        :raises TypeError:
            The flag does not have a corresponding ``Enum`` value.
        """

        try:
            # Resolve the flag
            flag = self.eset[flag]
        except KeyError:
            raise TypeError('Unknown bit flag %r' % flag)

        # Save the current bitflags
        previous = self.bitflags

        self.bitflags |= int(flag)
        self.flags.add(str(flag))

        # Call the notification callback if necessary
        if previous != self.bitflags and self._notify:
            self._notify()

    def discard(self, flag):
        """
        Discard a flag on the ``FlagSet`` instance.

        :param flag: The flag to clear.  May be an integer, a string,
                     or an ``Enum`` instance.
        """

        try:
            # Resolve the flag
            flag = self.eset[flag]
        except KeyError:
            return

        # Save the current bitflags
        previous = self.bitflags

        self.bitflags &= ~int(flag)
        self.flags.discard(str(flag))

        # Call the notification callback if necessary
        if previous != self.bitflags and self._notify:
            self._notify()

    def notify(self, notifier):
        """
        Register a routine to be called if the value of this ``FlagSet``
        instance is altered.

        :param notifier: A callable to be called.
        """

        self._notify = notifier


class EnumAttr(attrs.InvalidatingAttr):
    """
    An enumeration attribute.  This is a special object property,
    implemented using the descriptor protocol, that requires the
    property be a member of an enumeration.  Use ``EnumSet.attr`` to
    create instances of this class.
    """

    def __init__(self, eset, invalidator='invalidate'):
        """
        Initialize an ``EnumAttr`` instance.

        :param eset: The ``EnumSet`` instance controlling the
                     property.
        :type eset: ``EnumSet``
        :param str invalidator: The name of the method to call when
                                alterations result in a cache
                                invalidation.  Defaults to
                                "invalidate".
        """

        # Initialize the superclass
        super(EnumAttr, self).__init__(invalidator)

        # Save the EnumSet
        self.eset = eset

    def prepare(self, instance, value):
        """
        Canonicalize a value.  This implementation returns the
        corresponding ``Enum`` value from the ``EnumSet`` specified at
        initialization.

        :param value: The value to prepare.

        :returns: The prepared value.

        :raises AttributeError:
            The specified value is invalid.
        """

        try:
            return self.eset[value]
        except KeyError:
            raise AttributeError(
                'Invalid value for attribute %s: %r' % (self.attr_name, value)
            )


class FlagSetAttr(attrs.InvalidatingAttr):
    """
    A flag set attribute.  This is a special object property,
    implemented using the descriptor protocol, that requires the
    property to be a valid set of flags.  Use ``EnumSet.flags`` to
    create instances of this class.
    """

    def __init__(self, eset, invalidator='invalidate'):
        """
        Initialize a ``FlagSetAttr`` instance.

        :param eset: The ``EnumSet`` instance controlling the
                     property.
        :type eset: ``EnumSet``
        :param str invalidator: The name of the method to call when
                                alterations result in a cache
                                invalidation.  Defaults to
                                "invalidate".
        """

        # Initialize the superclass
        super(FlagSetAttr, self).__init__(invalidator)

        # Save the EnumSet
        self.eset = eset

    def prepare(self, instance, value):
        """
        Canonicalize a value.  This implementation returns a properly
        initialized ``FlagSet`` instance representing the flags
        present in the value.

        :param value: The value to prepare.

        :returns: The prepared value.

        :raises AttributeError:
            The specified value is invalid.
        """

        if value is None:
            value = self.eset.flagset()
        elif not isinstance(value, FlagSet):
            try:
                value = self.eset.flagset(value)
            except TypeError as err:
                raise AttributeError(
                    'Invalid value for attribute %s: %s' %
                    (self.attr_name, err)
                )
        elif value.eset != self.eset:
            raise AttributeError(
                'Invalid value for attribute %s: flag set '
                'enumeration mismatch' % self.attr_name
            )

        # Make sure the flag set is configured to call the correct
        # invalidation routine
        value.notify(self.get_invalidate(instance))

        return value
