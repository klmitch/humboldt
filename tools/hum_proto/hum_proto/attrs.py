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

_unset = object()


class InvalidatingAttr(object):
    """
    An invalidating attribute descriptor.  These descriptors call the
    ``invalidate()`` method on an instance if the value for which the
    descriptor is responsible is altered in any way.  The descriptor
    also provides a way for a value to be canonicalized before it is
    set.
    """

    def __init__(self, invalidator='invalidate'):
        """
        Initialize an ``InvalidatingAttr`` instance.

        :param str invalidator: The name of the method to call when
                                alterations result in a cache
                                invalidation.  Defaults to
                                "invalidate".
        """

        self.invalidator = invalidator

        # A unique attribute name to cache our values
        self._attr_name = '_inval_attr_%d' % id(self)

        # The name of the attribute, for error reporting by the
        # ``prepare()`` method
        self.attr_name = None

    def prepare(self, instance, value):
        """
        Canonicalize a value.  This implementation returns the value
        unchanged, but subclasses can convert the format or otherwise
        validate it.  The attribute name will be available in the
        ``attr_name`` instance attribute.

        :param instance: The instance where the value will be stored.
        :param value: The value to prepare.

        :returns: The prepared value.

        :raises AttributeError:
            The specified value is invalid.
        """

        return value

    def get_invalidate(self, instance):
        """
        Obtain the invalidation callable for an instance.

        :param instance: The instance to invalidate.

        :returns: A callable that, when called, invalidates the
                  appropriate cache.
        """

        return getattr(instance, self.invalidator)

    def __get__(self, instance, owner):
        """
        Implement the get operation of the descriptor protocol.

        :param instance: An instance of the class containing the
                         ``InvalidatingAttr`` instance, or ``None``
                         for references directly to the class.
        :param owner: The class containing the ``InvalidatingAttr``
                      instance.

        :returns: If ``instance`` is ``None``, returns the
                  ``InvalidatingAttr`` instance.  Otherwise, attempts
                  to retrieve the value of the attribute.

        :raises AttributeError:
            The attribute has not been set.
        """

        # Return ourself if instance is None, for introspection
        if instance is None:
            return self

        return getattr(instance, self._attr_name)

    def __set__(self, instance, value):
        """
        Implement the set operation of the descriptor protocol.

        :param instance: An instance of the class containing the
                         ``InvalidatingAttr`` instance.
        :param value: The desired new value of the attribute.

        :raises AttributeError:
            The specified value is invalid.
        """

        # Prepare the new value of the attribute
        value = self.prepare(instance, value)

        # Save the current value of the attribute
        prev = getattr(instance, self._attr_name, _unset)

        # Set the new value
        setattr(instance, self._attr_name, value)

        # If it was a change, invalidate the cache
        if prev != value:
            self.get_invalidate(instance)()

    def __delete__(self, instance):
        """
        Implement the delete operation of the descriptor protocol.

        :param instance: An instance of the class containing the
                         ``InvalidatingAttr`` instance.
        """

        # Delete the attribute
        delattr(instance, self._attr_name)

        # Invalidate the cache
        self.get_invalidate(instance)()


class FilterAttr(InvalidatingAttr):
    """
    A filtering attribute.  This is a function decorator, similar to
    ``@property``, that passes an incoming value through a function
    for normalization and value checking prior to setting it.
    """

    def __init__(self, func):
        """
        Initialize a ``FilterAttr`` instance.

        :param func: The callable to use to filter new values of the
                     attribute.  Like a property setter, this method
                     will be passed the proposed value, and should
                     return the canonical form.
        """

        # Initialize the superclass
        super(FilterAttr, self).__init__()

        # Replace the prepare function with the passed in function
        self.prepare = func


class InvalidatingAttrMeta(type):
    """
    A metaclass for classes utilizing ``InvalidatingAttr``.  This
    metaclass sets the attribute names for error reporting purposes.
    """

    def __init__(cls, name, bases, namespace):
        """
        Initialize a newly constructed class.

        :param str name: The name of the new class.
        :param tuple bases: A tuple of the class's base classes.
        :param dict namespace: The new class's namespace.
        """

        # Just search the namespace for InvalidatingAttr instances
        for attr_name, obj in namespace.items():
            if isinstance(obj, InvalidatingAttr):
                # Set the attribute name on them
                obj.attr_name = attr_name
